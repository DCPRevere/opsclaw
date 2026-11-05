//! `opsclaw_notify` — the ONE structured escalation tool (brief §6, DESIGN.md
//! §4 "Tool surface" item 3: "exactly one — the `escalate_to_human` /
//! `opsclaw_notify` split was a fork scar"). The payload is the product's
//! most visible artifact: severity, fully-qualified target, the observed
//! signals with actual numbers, the hypothesis, and a recommended action.
//!
//! Dedup lives here, not in the caller: this tool IS the anti-spam choke
//! point for escalation. It computes the fingerprint
//! (`incidents::fingerprint_for`) and looks for an already-open incident
//! (`IncidentRepo::find_open_by_fingerprint`) — a matching open incident
//! means this is a new OCCURRENCE of the same problem, so the tool reports
//! that plainly rather than opening a duplicate. An EXPIRED match
//! (`IncidentRepo::find_expired_by_fingerprint`) means the chain exhausted
//! unacked and the fault is still standing — the incident RE-OPENS
//! (`IncidentRepo::reopen`) instead of duplicating. Only a genuinely new
//! fingerprint (including a resolved one's — a fault back after a fix is
//! new) opens a new `Incident` row. Escalation-chain delivery (who
//! gets notified, ack_timeout, repeat_interval) is the scheduler's job
//! (`incidents::escalation`) once the incident exists — this tool's
//! responsibility ends at "the incident now exists (or already did)".

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::{Incident, IncidentState, RiskClass, Severity};
use crate::incidents::fingerprint_for;
use crate::tools::{Tool, ToolCtx, ToolError, ToolResult};

pub struct NotifyTool;

fn parse_severity(s: &str) -> Result<Severity, ToolError> {
    match s {
        "info" => Ok(Severity::Info),
        "warning" => Ok(Severity::Warning),
        "critical" => Ok(Severity::Critical),
        other => Err(ToolError::UserFacing(format!(
            "unknown severity {other:?}. Valid severities: info, warning, critical."
        ))),
    }
}

/// The closed fault_class vocabulary. Fingerprint identity hangs on this
/// label, and a model invents a fresh synonym per run when left free — one
/// live day produced dapr_sentry_cert_expired / dapr_cert_expired /
/// certificate_expired for the SAME expired CA (plus secret_key_missing vs
/// secret_missing_keys, image_not_found vs image_pull_backoff), so every
/// re-detection minted a new incident and dedup/re-open never matched.
/// `other` is the escape hatch; `resource` carries the specificity.
pub const FAULT_CLASSES: &[&str] = &[
    "crashloop",
    "oom_kill",
    "image_pull_failure",
    "cert_expired",
    "config_missing",
    "scheduling_failure",
    "volume_failure",
    "rollout_stuck",
    "resource_saturation",
    "error_rate",
    "queue_backlog",
    "target_unreachable",
    "other",
];

/// Open incidents, one per line, for the model to choose between.
fn describe_candidates(candidates: &[Incident]) -> String {
    if candidates.is_empty() {
        return "none".to_string();
    }
    candidates
        .iter()
        .map(|i| {
            let hypothesis: String = i.hypothesis.chars().take(160).collect();
            format!("{} — {hypothesis}", i.id)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Strip per-instance suffixes so the fingerprint anchors to the WORKLOAD,
/// not one pod's incarnation: deployment pods carry `-<template-hash>-<id>`
/// and statefulset pods `-<ordinal>`, both of which churn across restarts
/// while the fault stays the same. Applies to the last path segment only
/// (a `namespace/` prefix passes through untouched).
fn stable_resource(resource: &str) -> String {
    let (prefix, name) = match resource.rsplit_once('/') {
        Some((p, n)) => (Some(p), n),
        None => (None, resource),
    };
    let segs: Vec<&str> = name.split('-').collect();
    let is_hashy = |s: &str, min: usize| {
        s.len() >= min && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    };
    let keep = if segs.len() >= 3
        && is_hashy(segs[segs.len() - 1], 5)
        && is_hashy(segs[segs.len() - 2], 5)
        && segs[segs.len() - 2].chars().any(|c| c.is_ascii_digit())
    {
        // deployment pod: name-<template-hash>-<random id>
        segs.len() - 2
    } else if segs.len() >= 2 && segs[segs.len() - 1].chars().all(|c| c.is_ascii_digit()) {
        // statefulset pod: name-<ordinal>
        segs.len() - 1
    } else {
        segs.len()
    };
    let name = segs[..keep].join("-");
    match prefix {
        Some(p) => format!("{p}/{name}"),
        None => name,
    }
}

#[async_trait]
impl Tool for NotifyTool {
    fn name(&self) -> &'static str {
        "opsclaw_notify"
    }

    fn description(&self) -> &str {
        "Escalate a confirmed problem to a human. This is the ONLY way to raise an incident \
         — call it once you've confirmed a signal with a diagnostic tool and formed a \
         hypothesis, not on a single unconfirmed reading. Provide: severity, the \
         fully-qualified target, `fault_class` (one of a FIXED vocabulary — it is the \
         incident's dedup identity, so a repeat of the same problem must map to the same \
         label), `resource` (the specific thing affected within the target: prefer the \
         stable workload identity like namespace/deployment-name, never a pod instance \
         name — pod hash suffixes churn every restart; empty string if the fault has no \
         finer resource than the target itself), `evidence` (the observed signals WITH \
         ACTUAL NUMBERS), `hypothesis`, and an optional `recommended_action`. Calling this \
         again for the same target+fault_class+resource while it's still open attaches as \
         a new occurrence — it does not create a duplicate incident or double-page."
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["info", "warning", "critical"]},
                "target": {"type": "string", "description": "fully-qualified target"},
                "fault_class": {"type": "string", "enum": FAULT_CLASSES, "description": "the fault kind — the incident's dedup identity; pick the closest, use \"other\" only when nothing fits"},
                "resource": {"type": "string", "description": "the stable workload affected (e.g. namespace/deployment-name, never a pod instance name), or \"\" if none finer than the target"},
                "evidence": {"type": "string", "description": "observed signals with actual numbers"},
                "hypothesis": {"type": "string"},
                "recommended_action": {"type": "string"},
                "same_as": {"type": "string", "description": "id of an open incident this is the same fault as: attaches to it instead of opening a new one"},
                "distinct": {"type": "boolean", "description": "true only after notify listed open incidents of the same fault_class on this target and this is genuinely a different fault"}
            },
            "required": ["severity", "target", "fault_class", "resource", "evidence", "hypothesis"]
        })
    }

    fn risk(&self) -> RiskClass {
        // Opening an incident has no remote side effect (nothing runs
        // against a target), so this is never gated by autonomy — it's a
        // daemon-local write, not a command dispatched through policy.
        RiskClass::Read
    }

    fn is_action(&self) -> bool {
        // Still an ACTION for the duplicate-call-guard's purposes (it
        // writes a row) even though it carries no policy risk.
        true
    }

    fn allowed_in_heartbeat(&self) -> bool {
        true
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<ToolResult, ToolError> {
        let repo = ctx.incidents.as_ref().ok_or_else(|| {
            ToolError::Internal("opsclaw_notify called with no incident store wired".to_string())
        })?;

        let severity = args["severity"]
            .as_str()
            .ok_or_else(|| {
                ToolError::UserFacing("opsclaw_notify requires \"severity\"".to_string())
            })
            .and_then(parse_severity)?;
        let target_str = args["target"].as_str().ok_or_else(|| {
            ToolError::UserFacing("opsclaw_notify requires \"target\"".to_string())
        })?;
        let fault_class = args["fault_class"].as_str().ok_or_else(|| {
            ToolError::UserFacing("opsclaw_notify requires \"fault_class\"".to_string())
        })?;
        // Enforce the vocabulary server-side too — schema enums are advisory
        // to some providers, and an invented synonym silently forks the
        // dedup identity. The error teaches the list so the retry lands.
        if !FAULT_CLASSES.contains(&fault_class) {
            return Err(ToolError::UserFacing(format!(
                "unknown fault_class {fault_class:?} — it is the incident's dedup identity and \
                 must come from the fixed vocabulary: {}. Pick the closest; use \"other\" only \
                 when nothing fits (resource carries the specificity).",
                FAULT_CLASSES.join(", ")
            )));
        }
        let resource = stable_resource(args["resource"].as_str().unwrap_or(""));
        let resource = resource.as_str();
        let evidence = args["evidence"].as_str().ok_or_else(|| {
            ToolError::UserFacing("opsclaw_notify requires \"evidence\"".to_string())
        })?;
        let hypothesis = args["hypothesis"].as_str().ok_or_else(|| {
            ToolError::UserFacing("opsclaw_notify requires \"hypothesis\"".to_string())
        })?;
        let recommended_action = args["recommended_action"].as_str().map(str::to_string);

        let target = ctx.resolve_target(target_str)?;
        let fingerprint = fingerprint_for(&target, fault_class, resource);

        let existing = repo
            .find_open_by_fingerprint(&fingerprint)
            .await
            .map_err(|e| ToolError::Internal(format!("incident lookup failed: {e}")))?;

        if let Some(incident) = existing {
            label_incident(ctx, incident.id).await;
            return Ok(ToolResult {
                output: format!(
                    "already tracking this as incident {} (opened {}, {} notifications sent \
                     so far) — attached as a new occurrence, not a new incident.",
                    incident.id,
                    incident.opened_at.to_rfc3339(),
                    incident.notify_count
                ),
            });
        }

        // An EXPIRED match (chain exhausted, never acked) re-opens rather
        // than duplicates: the fault never went away, so a fresh row would
        // churn a full notification cycle per re-detection forever. Only a
        // RESOLVED incident's fingerprint opens a genuinely new incident.
        let expired = repo
            .find_expired_by_fingerprint(&fingerprint)
            .await
            .map_err(|e| ToolError::Internal(format!("incident lookup failed: {e}")))?;
        if let Some(incident) = expired {
            repo.reopen(incident.id, Utc::now())
                .await
                .map_err(|e| ToolError::Internal(format!("incident reopen failed: {e}")))?;
            label_incident(ctx, incident.id).await;
            return Ok(ToolResult {
                output: format!(
                    "re-opened incident {} (originally opened {}, expired unacknowledged after \
                     {} notifications) — same fault re-detected; a single re-open notification \
                     goes out, then the escalation chain resumes only if still unacknowledged.",
                    incident.id,
                    incident.opened_at.to_rfc3339(),
                    incident.notify_count
                ),
            });
        }

        // Same target and fault class but a different resource string is
        // often the SAME fault named differently (one missing secret breaking
        // three workloads was filed twice on 2026-11-04). Show the open
        // candidates and make the model say which it is.
        let same_as = args["same_as"].as_str().filter(|s| !s.trim().is_empty());
        let distinct = args["distinct"].as_bool().unwrap_or(false);
        let candidates: Vec<Incident> = repo
            .list(false, 500)
            .await
            .map_err(|e| ToolError::Internal(format!("incident lookup failed: {e}")))?
            .into_iter()
            .filter(|i| i.target == target && i.fault_class == fault_class)
            .collect();
        if let Some(id) = same_as {
            let Some(incident) = candidates.iter().find(|i| i.id.to_string() == id) else {
                return Err(ToolError::UserFacing(format!(
                    "same_as {id:?} is not an open {fault_class} incident on {target}. Open ones: {}",
                    describe_candidates(&candidates)
                )));
            };
            label_incident(ctx, incident.id).await;
            return Ok(ToolResult {
                output: format!(
                    "attached to incident {} (opened {}) as a new occurrence of the same fault, \
                     not a new incident.",
                    incident.id,
                    incident.opened_at.to_rfc3339()
                ),
            });
        }
        if !candidates.is_empty() && !distinct {
            return Err(ToolError::UserFacing(format!(
                "not opened yet: {target} already has open {fault_class} incident(s): {}. If \
                 this is the same fault, call opsclaw_notify again with same_as set to that \
                 incident's id. If it is a genuinely different fault, call again with \
                 distinct: true.",
                describe_candidates(&candidates)
            )));
        }

        let now = Utc::now();
        let incident = Incident {
            id: Uuid::new_v4(),
            fingerprint,
            fault_class: fault_class.to_string(),
            target,
            severity,
            state: IncidentState::Active,
            signals: evidence.to_string(),
            hypothesis: hypothesis.to_string(),
            recommended_action,
            opened_at: now,
            reopened_at: None,
            acked_at: None,
            acked_by: None,
            resolved_at: None,
            last_notified_at: None,
            notify_count: 0,
            escalation_step: 0,
            step_started_at: None,
        };
        repo.insert(&incident)
            .await
            .map_err(|e| ToolError::Internal(format!("incident insert failed: {e}")))?;
        label_incident(ctx, incident.id).await;

        Ok(ToolResult {
            output: format!(
                "opened incident {} (severity {:?}) — the escalation chain will notify per its \
                 configured priority; this call does not itself send anything.",
                incident.id, severity
            ),
        })
    }
}

/// Record what this turn read on the incident, so each reader sees only
/// the evidence they may (`crate::access`). Best-effort and loud: the
/// incident itself matters more than its labels.
async fn label_incident(ctx: &ToolCtx, id: Uuid) {
    let (Some(labels), Some(repo)) = (&ctx.call.labels, &ctx.call.repo) else { return };
    let labels = labels.snapshot();
    if labels.is_empty() {
        return;
    }
    if let Err(e) = repo.add_labels("incident", &id.to_string(), &labels).await {
        tracing::warn!(incident = %id, error = %e, "incident labels not stored");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::IncidentRepo;
    use crate::db::memory::InMemoryDb;
    use crate::domain::{FqTarget, Principal};
    use crate::policy::{CommandRequest, PolicyExecute, PolicyOutcome};
    use std::sync::Arc;

    struct NoopPolicy;
    #[async_trait]
    impl PolicyExecute for NoopPolicy {
        async fn execute(&self, _req: CommandRequest) -> crate::Result<PolicyOutcome> {
            Ok(PolicyOutcome::EStopped)
        }
    }

    fn target() -> FqTarget {
        FqTarget::new("example", "prod", "web-1")
    }

    fn ctx_with(incidents: Arc<dyn IncidentRepo>) -> ToolCtx {
        ToolCtx {
            call: Default::default(),
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![target()],
            incidents: Some(incidents),
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: None,
            runbooks: None,
        }
    }

    fn base_args() -> Value {
        json!({
            "severity": "critical",
            "target": "example::prod::web-1",
            "fault_class": "resource_saturation",
            "resource": "",
            "evidence": "cpu at 97% for 8 minutes",
            "hypothesis": "runaway worker process"
        })
    }

    #[tokio::test]
    async fn opens_a_new_incident_on_first_call() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        let r = NotifyTool.call(&ctx, base_args()).await.unwrap();
        assert!(r.output.contains("opened incident"));

        let open = db
            .find_open_by_fingerprint(&fingerprint_for(&target(), "resource_saturation", ""))
            .await
            .unwrap();
        assert!(open.is_some());
        let incident = open.unwrap();
        assert_eq!(incident.severity, Severity::Critical);
        assert_eq!(incident.signals, "cpu at 97% for 8 minutes");
        assert_eq!(incident.hypothesis, "runaway worker process");
        assert_eq!(incident.state, IncidentState::Active);
    }

    #[tokio::test]
    async fn second_call_with_same_fingerprint_attaches_not_duplicates() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        NotifyTool.call(&ctx, base_args()).await.unwrap();
        let r2 = NotifyTool.call(&ctx, base_args()).await.unwrap();
        assert!(r2.output.contains("already tracking"), "{}", r2.output);

        let all = db.list(true, 100).await.unwrap();
        assert_eq!(all.len(), 1, "must not create a second incident row");
    }

    #[test]
    fn stable_resource_strips_pod_instance_suffixes_only() {
        // deployment pod → workload
        assert_eq!(
            stable_resource("dapr-system/dapr-sentry-677b4c4c8d-jq49j"),
            "dapr-system/dapr-sentry"
        );
        assert_eq!(
            stable_resource("prod-example-api-admin-fbcd9dc96-csv2x"),
            "prod-example-api-admin"
        );
        // statefulset pod → workload
        assert_eq!(
            stable_resource("elastic-backend/elasticsearch-0"),
            "elastic-backend/elasticsearch"
        );
        assert_eq!(stable_resource("apisix-etcd-1"), "apisix-etcd");
        // already-stable names pass through
        assert_eq!(stable_resource("prod-backend/notifier"), "prod-backend/notifier");
        assert_eq!(stable_resource("elasticsearch-latest"), "elasticsearch-latest");
        assert_eq!(stable_resource(""), "");
    }

    /// One missing secret breaking several workloads, named differently by
    /// a later scan, must not become a second incident unnoticed.
    #[tokio::test]
    async fn a_second_incident_of_the_same_class_on_the_target_needs_a_decision() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        let mut first = base_args();
        first["fault_class"] = json!("config_missing");
        first["resource"] = json!("elastic-backend/elasticsearch");
        NotifyTool.call(&ctx, first).await.unwrap();
        let open = db.list(false, 100).await.unwrap();
        assert_eq!(open.len(), 1);
        let id = open[0].id.to_string();

        let mut again = base_args();
        again["fault_class"] = json!("config_missing");
        again["resource"] = json!("elastic-backend/kibana");
        let err = NotifyTool.call(&ctx, again.clone()).await.unwrap_err();
        let ToolError::UserFacing(msg) = err else { panic!("expected UserFacing") };
        assert!(msg.contains(&id) && msg.contains("same_as"), "{msg}");
        assert_eq!(db.list(false, 100).await.unwrap().len(), 1, "nothing opened yet");

        let mut same = again.clone();
        same["same_as"] = json!(id);
        let out = NotifyTool.call(&ctx, same).await.unwrap().output;
        assert!(out.contains("attached to incident"), "{out}");
        assert_eq!(db.list(false, 100).await.unwrap().len(), 1, "attached, not duplicated");

        let mut bad = again.clone();
        bad["same_as"] = json!("not-an-open-incident");
        assert!(NotifyTool.call(&ctx, bad).await.is_err());

        let mut distinct = again;
        distinct["distinct"] = json!(true);
        NotifyTool.call(&ctx, distinct).await.unwrap();
        assert_eq!(db.list(false, 100).await.unwrap().len(), 2, "a confirmed distinct fault opens");
    }

    #[tokio::test]
    async fn invented_fault_class_is_rejected_with_the_vocabulary() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        let mut args = base_args();
        args["fault_class"] = json!("dapr_sentry_cert_expired");
        let err = NotifyTool.call(&ctx, args).await.unwrap_err();
        match err {
            ToolError::UserFacing(msg) => {
                assert!(msg.contains("cert_expired"), "error must teach the vocabulary: {msg}")
            }
            other => panic!("expected UserFacing, got {other:?}"),
        }
        assert!(db.list(true, 100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn pod_instance_resources_land_on_the_same_fingerprint() {
        // Two detections of one fault, reported against different pod
        // incarnations of the same workload, must be ONE incident.
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        let mut first = base_args();
        first["resource"] = json!("dapr-system/dapr-sentry-677b4c4c8d-jq49j");
        NotifyTool.call(&ctx, first).await.unwrap();
        let mut second = base_args();
        second["resource"] = json!("dapr-system/dapr-sentry-5d9f8b7c66-x2mlp");
        let r = NotifyTool.call(&ctx, second).await.unwrap();
        assert!(r.output.contains("already tracking"), "{}", r.output);
        assert_eq!(db.list(true, 100).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn expired_incident_is_reopened_not_duplicated() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        NotifyTool.call(&ctx, base_args()).await.unwrap();
        let fp = fingerprint_for(&target(), "resource_saturation", "");
        let original = db.find_open_by_fingerprint(&fp).await.unwrap().unwrap();
        db.set_state(original.id, IncidentState::Expired, None).await.unwrap();

        let r = NotifyTool.call(&ctx, base_args()).await.unwrap();
        assert!(r.output.contains("re-opened incident"), "{}", r.output);

        let all = db.list(true, 100).await.unwrap();
        assert_eq!(all.len(), 1, "the expired row re-opens; no second incident row");
        let reopened = db.find_open_by_fingerprint(&fp).await.unwrap().unwrap();
        assert_eq!(reopened.id, original.id, "same incident id preserved");
        assert_eq!(reopened.state, IncidentState::Active);
        assert!(reopened.reopened_at.is_some());
        assert_eq!(
            reopened.opened_at, original.opened_at,
            "opened_at keeps the original detection for age-tracking"
        );
    }

    #[tokio::test]
    async fn resolved_incident_produces_a_fresh_incident_on_redetection() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        NotifyTool.call(&ctx, base_args()).await.unwrap();
        let fp = fingerprint_for(&target(), "resource_saturation", "");
        let original = db.find_open_by_fingerprint(&fp).await.unwrap().unwrap();
        db.set_state(original.id, IncidentState::Resolved, None).await.unwrap();

        // A fault back after a FIX is genuinely new — a fresh row, never a
        // re-open of the resolved one.
        let r = NotifyTool.call(&ctx, base_args()).await.unwrap();
        assert!(r.output.contains("opened incident"), "{}", r.output);
        let all = db.list(true, 100).await.unwrap();
        assert_eq!(all.len(), 2);
        let reopened = db.find_open_by_fingerprint(&fp).await.unwrap().unwrap();
        assert_ne!(reopened.id, original.id);
        assert!(reopened.reopened_at.is_none());
    }

    #[tokio::test]
    async fn different_fault_class_opens_a_distinct_incident() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        NotifyTool.call(&ctx, base_args()).await.unwrap();

        let mut second = base_args();
        second["fault_class"] = json!("volume_failure");
        NotifyTool.call(&ctx, second).await.unwrap();

        let all = db.list(true, 100).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn recommended_action_is_optional() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db.clone());
        NotifyTool.call(&ctx, base_args()).await.unwrap();
        let incident = db
            .find_open_by_fingerprint(&fingerprint_for(&target(), "resource_saturation", ""))
            .await
            .unwrap()
            .unwrap();
        assert!(incident.recommended_action.is_none());
    }

    #[tokio::test]
    async fn unknown_severity_is_user_facing() {
        let db: Arc<dyn IncidentRepo> = Arc::new(InMemoryDb::new());
        let ctx = ctx_with(db);
        let mut args = base_args();
        args["severity"] = json!("urgent");
        let err = NotifyTool.call(&ctx, args).await.unwrap_err();
        assert!(matches!(err, ToolError::UserFacing(_)));
    }

    #[tokio::test]
    async fn missing_incident_store_is_an_internal_fault() {
        let ctx = ToolCtx {
            call: Default::default(),
            principal: Principal::Agent { job: None },
            policy: Arc::new(NoopPolicy),
            known_targets: vec![target()],
            incidents: None,
            approvals: None,
            runbook_runs: None,
            memory: None,
            config: None,
            endpoints: None,
            runbooks: None,
        };
        let err = NotifyTool.call(&ctx, base_args()).await.unwrap_err();
        assert!(matches!(err, ToolError::Internal(_)));
    }
}
