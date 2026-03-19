//! Escalation engine — tiered notification with ack timeout and state machine.
//!
//! When OpsClaw detects an issue it cannot auto-remediate, it creates an
//! [`Escalation`] that walks through a prioritised contact list until someone
//! acknowledges or the list is exhausted.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Policy & contact types
// ---------------------------------------------------------------------------

/// Defines how escalations are routed and timed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    pub contacts: Vec<EscalationContact>,
    /// Seconds to wait for an ack before escalating to the next contact (default 300).
    #[serde(default = "default_ack_timeout")]
    pub ack_timeout_secs: u64,
    /// Maximum number of contacts to try (default: all).
    #[serde(default)]
    pub max_escalations: Option<usize>,
    /// Seconds between repeat notifications while still unacked (default 900).
    #[serde(default = "default_repeat_interval")]
    pub repeat_interval_secs: u64,
}

fn default_ack_timeout() -> u64 {
    300
}
fn default_repeat_interval() -> u64 {
    900
}

impl Default for EscalationPolicy {
    fn default() -> Self {
        Self {
            contacts: Vec::new(),
            ack_timeout_secs: default_ack_timeout(),
            max_escalations: None,
            repeat_interval_secs: default_repeat_interval(),
        }
    }
}

/// A single on-call contact in the escalation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationContact {
    pub name: String,
    /// Channel kind: `"telegram"`, `"slack"`, `"email"`, etc.
    pub channel: String,
    /// Destination address (chat ID, email, etc.).
    pub target: String,
    /// Lower value = notified first.
    #[serde(default)]
    pub priority: u32,
}

// ---------------------------------------------------------------------------
// Escalation record
// ---------------------------------------------------------------------------

/// Tracks a single escalation through the contact chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Escalation {
    pub id: String,
    pub incident_id: String,
    pub target_name: String,
    pub created_at: DateTime<Utc>,
    pub status: EscalationStatus,
    pub current_contact_idx: usize,
    pub notifications_sent: Vec<NotificationRecord>,
    pub diagnosis_summary: String,
    pub suggested_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscalationStatus {
    Active,
    Acknowledged {
        by: String,
        at: DateTime<Utc>,
    },
    Resolved {
        by: String,
        at: DateTime<Utc>,
        resolution: String,
    },
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    pub contact: String,
    pub sent_at: DateTime<Utc>,
    pub channel: String,
    pub message_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Actions emitted by the state machine
// ---------------------------------------------------------------------------

/// An action the caller should execute after [`EscalationManager::check_timeouts`].
#[derive(Debug, Clone)]
pub enum EscalationAction {
    /// Re-notify the current contact (repeat interval elapsed).
    NotifyContact {
        escalation_id: String,
        contact: EscalationContact,
        message: String,
    },
    /// Ack timeout elapsed — escalate to the next contact.
    EscalateToNext {
        escalation_id: String,
        next_contact: EscalationContact,
    },
    /// All contacts exhausted with no ack.
    Expired { escalation_id: String },
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Manages active escalations and their lifecycle.
#[derive(Debug)]
pub struct EscalationManager {
    policy: EscalationPolicy,
    active: HashMap<String, Escalation>,
    store_path: PathBuf,
}

impl EscalationManager {
    pub fn new(policy: EscalationPolicy, store_path: PathBuf) -> Self {
        Self {
            policy,
            active: HashMap::new(),
            store_path,
        }
    }

    /// Sorted contacts (by priority ascending).
    fn sorted_contacts(&self) -> Vec<EscalationContact> {
        let mut contacts = self.policy.contacts.clone();
        contacts.sort_by_key(|c| c.priority);
        contacts
    }

    /// Effective max escalations (capped to contact count).
    fn max_escalations(&self) -> usize {
        let contacts_len = self.policy.contacts.len();
        self.policy
            .max_escalations
            .map(|m| m.min(contacts_len))
            .unwrap_or(contacts_len)
    }

    /// Create a new escalation from an incident.
    pub fn create(
        &mut self,
        incident_id: &str,
        target: &str,
        diagnosis: &str,
        actions: &[String],
    ) -> &Escalation {
        let id = uuid::Uuid::new_v4().to_string();
        let escalation = Escalation {
            id: id.clone(),
            incident_id: incident_id.to_string(),
            target_name: target.to_string(),
            created_at: Utc::now(),
            status: EscalationStatus::Active,
            current_contact_idx: 0,
            notifications_sent: Vec::new(),
            diagnosis_summary: diagnosis.to_string(),
            suggested_actions: actions.to_vec(),
        };
        self.active.insert(id.clone(), escalation);
        self.active.get(&id).unwrap()
    }

    /// Check for escalations that need attention (ack timeout or repeat interval).
    pub fn check_timeouts(&mut self, now: DateTime<Utc>) -> Vec<EscalationAction> {
        let mut actions = Vec::new();
        let sorted = self.sorted_contacts();
        let max = self.max_escalations();
        let ack_timeout = chrono::Duration::seconds(self.policy.ack_timeout_secs as i64);
        let repeat_interval = chrono::Duration::seconds(self.policy.repeat_interval_secs as i64);

        let ids: Vec<String> = self
            .active
            .values()
            .filter(|e| e.status == EscalationStatus::Active)
            .map(|e| e.id.clone())
            .collect();

        for id in ids {
            let esc = self.active.get(&id).unwrap();
            let current_idx = esc.current_contact_idx;

            // Find the last notification time for the current contact level.
            let last_sent = esc
                .notifications_sent
                .iter()
                .filter(|n| {
                    sorted
                        .get(current_idx)
                        .map(|c| c.name == n.contact)
                        .unwrap_or(false)
                })
                .map(|n| n.sent_at)
                .max();

            let time_since_creation = now - esc.created_at;

            match last_sent {
                None => {
                    // First notification for this contact — hasn't been sent yet.
                    // This shouldn't normally happen (create + first notify are paired),
                    // but handle it gracefully.
                    if let Some(contact) = sorted.get(current_idx) {
                        let msg = format_escalation_message(esc, &sorted, false);
                        actions.push(EscalationAction::NotifyContact {
                            escalation_id: id,
                            contact: contact.clone(),
                            message: msg,
                        });
                    }
                }
                Some(last) => {
                    let since_last = now - last;

                    // Check ack timeout — should we escalate to next contact?
                    if since_last >= ack_timeout {
                        let next_idx = current_idx + 1;
                        if next_idx < max && next_idx < sorted.len() {
                            // Escalate to next contact.
                            let next_contact = sorted[next_idx].clone();
                            let esc_mut = self.active.get_mut(&id).unwrap();
                            esc_mut.current_contact_idx = next_idx;
                            actions.push(EscalationAction::EscalateToNext {
                                escalation_id: id,
                                next_contact,
                            });
                        } else {
                            // All contacts exhausted.
                            let esc_mut = self.active.get_mut(&id).unwrap();
                            esc_mut.status = EscalationStatus::Expired;
                            actions.push(EscalationAction::Expired { escalation_id: id });
                        }
                    } else if time_since_creation >= repeat_interval
                        && since_last >= repeat_interval
                    {
                        // Repeat notification to current contact.
                        if let Some(contact) = sorted.get(current_idx) {
                            let esc_ref = self.active.get(&id).unwrap();
                            let msg = format_escalation_message(esc_ref, &sorted, true);
                            actions.push(EscalationAction::NotifyContact {
                                escalation_id: id,
                                contact: contact.clone(),
                                message: msg,
                            });
                        }
                    }
                }
            }
        }
        actions
    }

    /// Record that a notification was sent.
    pub fn record_notification(
        &mut self,
        escalation_id: &str,
        contact_name: &str,
        channel: &str,
        message_id: Option<String>,
    ) -> Result<()> {
        let esc = self
            .active
            .get_mut(escalation_id)
            .context("Escalation not found")?;
        esc.notifications_sent.push(NotificationRecord {
            contact: contact_name.to_string(),
            sent_at: Utc::now(),
            channel: channel.to_string(),
            message_id,
        });
        Ok(())
    }

    /// Mark an escalation as acknowledged.
    pub fn acknowledge(&mut self, escalation_id: &str, by: &str) -> Result<()> {
        let esc = self
            .active
            .get_mut(escalation_id)
            .context("Escalation not found")?;
        if esc.status != EscalationStatus::Active {
            bail!("Cannot acknowledge escalation in {:?} state", esc.status);
        }
        esc.status = EscalationStatus::Acknowledged {
            by: by.to_string(),
            at: Utc::now(),
        };
        Ok(())
    }

    /// Mark an escalation as resolved.
    pub fn resolve(&mut self, escalation_id: &str, by: &str, resolution: &str) -> Result<()> {
        let esc = self
            .active
            .get_mut(escalation_id)
            .context("Escalation not found")?;
        match &esc.status {
            EscalationStatus::Resolved { .. } => {
                bail!("Escalation is already resolved");
            }
            EscalationStatus::Expired => {
                bail!("Cannot resolve an expired escalation");
            }
            _ => {}
        }
        esc.status = EscalationStatus::Resolved {
            by: by.to_string(),
            at: Utc::now(),
            resolution: resolution.to_string(),
        };
        Ok(())
    }

    /// Get an escalation by ID.
    pub fn get(&self, escalation_id: &str) -> Option<&Escalation> {
        self.active.get(escalation_id)
    }

    /// List all active (non-resolved, non-expired) escalations.
    pub fn list_active(&self) -> Vec<&Escalation> {
        self.active
            .values()
            .filter(|e| {
                matches!(
                    e.status,
                    EscalationStatus::Active | EscalationStatus::Acknowledged { .. }
                )
            })
            .collect()
    }

    /// List all escalations.
    pub fn list_all(&self) -> Vec<&Escalation> {
        self.active.values().collect()
    }

    /// Persist state to disk as JSON.
    pub fn save(&self) -> Result<()> {
        let data = SavedState {
            policy: self.policy.clone(),
            escalations: self.active.clone(),
        };
        let json = serde_json::to_string_pretty(&data)?;
        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.store_path, json).with_context(|| {
            format!(
                "Failed to save escalation state to {}",
                self.store_path.display()
            )
        })?;
        Ok(())
    }

    /// Load state from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read escalation state from {}", path.display()))?;
        let data: SavedState = serde_json::from_str(&json)?;
        Ok(Self {
            policy: data.policy,
            active: data.escalations,
            store_path: path.to_path_buf(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SavedState {
    policy: EscalationPolicy,
    escalations: HashMap<String, Escalation>,
}

// ---------------------------------------------------------------------------
// Message formatting
// ---------------------------------------------------------------------------

/// Format a human-readable escalation message.
pub fn format_escalation_message(
    escalation: &Escalation,
    sorted_contacts: &[EscalationContact],
    is_repeat: bool,
) -> String {
    let mut buf = String::new();

    let repeat_tag = if is_repeat { " (REMINDER)" } else { "" };
    let _ = writeln!(
        buf,
        "\u{1f6a8} ESCALATION{} \u{2014} {}",
        repeat_tag, escalation.target_name
    );
    let _ = writeln!(buf);
    let _ = writeln!(buf, "{}", escalation.diagnosis_summary);

    if !escalation.suggested_actions.is_empty() {
        let _ = writeln!(buf);
        let _ = writeln!(buf, "Suggested actions:");
        for (i, action) in escalation.suggested_actions.iter().enumerate() {
            let _ = writeln!(buf, "{}. {}", i + 1, action);
        }
    }

    // Escalation progress.
    let max = sorted_contacts.len();
    let attempt = escalation.current_contact_idx + 1;
    let _ = writeln!(buf);
    let _ = writeln!(buf, "Escalation attempt {attempt}/{max}.");

    // Previous contacts that didn't respond.
    if escalation.current_contact_idx > 0 {
        let previous: Vec<&str> = sorted_contacts[..escalation.current_contact_idx]
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        let _ = writeln!(
            buf,
            "Previously notified: {} (no response).",
            previous.join(", ")
        );
    }

    let _ = writeln!(buf);
    let _ = write!(
        buf,
        "Reply \"ack\" to acknowledge, or \"resolve <description>\" to close."
    );

    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn test_policy() -> EscalationPolicy {
        EscalationPolicy {
            contacts: vec![
                EscalationContact {
                    name: "Primary".into(),
                    channel: "telegram".into(),
                    target: "111".into(),
                    priority: 1,
                },
                EscalationContact {
                    name: "Secondary".into(),
                    channel: "email".into(),
                    target: "backup@co.com".into(),
                    priority: 2,
                },
                EscalationContact {
                    name: "Tertiary".into(),
                    channel: "slack".into(),
                    target: "#ops".into(),
                    priority: 3,
                },
            ],
            ack_timeout_secs: 300,
            max_escalations: None,
            repeat_interval_secs: 900,
        }
    }

    #[test]
    fn create_escalation() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = EscalationManager::new(test_policy(), dir.path().join("esc.json"));

        let esc = mgr.create("inc-1", "prod-web", "Container down", &["restart".into()]);
        assert_eq!(esc.status, EscalationStatus::Active);
        assert_eq!(esc.incident_id, "inc-1");
        assert_eq!(esc.target_name, "prod-web");
        assert_eq!(esc.current_contact_idx, 0);
    }

    #[test]
    fn contacts_sorted_by_priority() {
        let mut policy = test_policy();
        // Reverse the priority ordering in the vec.
        policy.contacts.reverse();
        let mgr = EscalationManager::new(policy, PathBuf::from("/tmp/test.json"));
        let sorted = mgr.sorted_contacts();
        assert_eq!(sorted[0].name, "Primary");
        assert_eq!(sorted[1].name, "Secondary");
        assert_eq!(sorted[2].name, "Tertiary");
    }

    #[test]
    fn acknowledge_stops_escalation() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = EscalationManager::new(test_policy(), dir.path().join("esc.json"));

        let id = mgr.create("inc-1", "web", "down", &[]).id.clone();
        mgr.record_notification(&id, "Primary", "telegram", None)
            .unwrap();

        mgr.acknowledge(&id, "alice").unwrap();

        let esc = mgr.get(&id).unwrap();
        assert!(matches!(esc.status, EscalationStatus::Acknowledged { .. }));

        // check_timeouts should produce no actions for acked escalation.
        let now = Utc::now() + Duration::seconds(600);
        let actions = mgr.check_timeouts(now);
        assert!(actions.is_empty());
    }

    #[test]
    fn resolve_from_active() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = EscalationManager::new(test_policy(), dir.path().join("esc.json"));

        let id = mgr.create("inc-1", "web", "down", &[]).id.clone();
        mgr.resolve(&id, "bob", "restarted container").unwrap();

        let esc = mgr.get(&id).unwrap();
        match &esc.status {
            EscalationStatus::Resolved { by, resolution, .. } => {
                assert_eq!(by, "bob");
                assert_eq!(resolution, "restarted container");
            }
            other => panic!("Expected Resolved, got {:?}", other),
        }
    }

    #[test]
    fn resolve_from_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = EscalationManager::new(test_policy(), dir.path().join("esc.json"));

        let id = mgr.create("inc-1", "web", "down", &[]).id.clone();
        mgr.acknowledge(&id, "alice").unwrap();
        mgr.resolve(&id, "alice", "fixed").unwrap();

        let esc = mgr.get(&id).unwrap();
        assert!(matches!(esc.status, EscalationStatus::Resolved { .. }));
    }

    #[test]
    fn cannot_ack_already_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = EscalationManager::new(test_policy(), dir.path().join("esc.json"));

        let id = mgr.create("inc-1", "web", "down", &[]).id.clone();
        mgr.resolve(&id, "bob", "done").unwrap();

        let result = mgr.acknowledge(&id, "alice");
        assert!(result.is_err());
    }

    #[test]
    fn cannot_resolve_expired() {
        let dir = tempfile::tempdir().unwrap();
        let mut policy = test_policy();
        policy.contacts = vec![EscalationContact {
            name: "Only".into(),
            channel: "telegram".into(),
            target: "111".into(),
            priority: 1,
        }];
        let mut mgr = EscalationManager::new(policy, dir.path().join("esc.json"));

        let id = mgr.create("inc-1", "web", "down", &[]).id.clone();
        mgr.record_notification(&id, "Only", "telegram", None)
            .unwrap();

        // Trigger timeout → expire (single contact).
        let now = Utc::now() + Duration::seconds(600);
        let actions = mgr.check_timeouts(now);
        assert!(actions
            .iter()
            .any(|a| matches!(a, EscalationAction::Expired { .. })));

        let result = mgr.resolve(&id, "bob", "too late");
        assert!(result.is_err());
    }

    #[test]
    fn timeout_escalates_to_next_contact() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = EscalationManager::new(test_policy(), dir.path().join("esc.json"));

        let id = mgr.create("inc-1", "web", "down", &[]).id.clone();
        mgr.record_notification(&id, "Primary", "telegram", None)
            .unwrap();

        // 6 minutes later — past ack_timeout (300s).
        let now = Utc::now() + Duration::seconds(360);
        let actions = mgr.check_timeouts(now);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            EscalationAction::EscalateToNext { next_contact, .. } => {
                assert_eq!(next_contact.name, "Secondary");
            }
            other => panic!("Expected EscalateToNext, got {:?}", other),
        }

        // Verify current_contact_idx was advanced.
        let esc = mgr.get(&id).unwrap();
        assert_eq!(esc.current_contact_idx, 1);
    }

    #[test]
    fn all_contacts_exhausted_expires() {
        let dir = tempfile::tempdir().unwrap();
        let mut policy = test_policy();
        policy.contacts = vec![
            EscalationContact {
                name: "A".into(),
                channel: "telegram".into(),
                target: "1".into(),
                priority: 1,
            },
            EscalationContact {
                name: "B".into(),
                channel: "email".into(),
                target: "b@x.com".into(),
                priority: 2,
            },
        ];
        let mut mgr = EscalationManager::new(policy, dir.path().join("esc.json"));

        let id = mgr.create("inc-1", "web", "down", &[]).id.clone();
        mgr.record_notification(&id, "A", "telegram", None).unwrap();

        // First timeout → escalate to B.
        let t1 = Utc::now() + Duration::seconds(360);
        mgr.check_timeouts(t1);
        mgr.record_notification(&id, "B", "email", None).unwrap();

        // Second timeout → expire.
        let t2 = Utc::now() + Duration::seconds(720);
        let actions = mgr.check_timeouts(t2);
        assert!(actions
            .iter()
            .any(|a| matches!(a, EscalationAction::Expired { .. })));

        let esc = mgr.get(&id).unwrap();
        assert_eq!(esc.status, EscalationStatus::Expired);
    }

    #[test]
    fn max_escalations_limits_contacts() {
        let dir = tempfile::tempdir().unwrap();
        let mut policy = test_policy();
        policy.max_escalations = Some(2); // Only try first 2 of 3 contacts.
        let mut mgr = EscalationManager::new(policy, dir.path().join("esc.json"));

        let id = mgr.create("inc-1", "web", "down", &[]).id.clone();
        mgr.record_notification(&id, "Primary", "telegram", None)
            .unwrap();

        // Escalate to Secondary.
        let t1 = Utc::now() + Duration::seconds(360);
        mgr.check_timeouts(t1);
        mgr.record_notification(&id, "Secondary", "email", None)
            .unwrap();

        // Next timeout should expire, not escalate to Tertiary.
        let t2 = Utc::now() + Duration::seconds(720);
        let actions = mgr.check_timeouts(t2);
        assert!(actions
            .iter()
            .any(|a| matches!(a, EscalationAction::Expired { .. })));
    }

    #[test]
    fn message_formatting() {
        let policy = test_policy();
        let sorted = {
            let mut c = policy.contacts.clone();
            c.sort_by_key(|c| c.priority);
            c
        };

        let esc = Escalation {
            id: "esc-1".into(),
            incident_id: "inc-1".into(),
            target_name: "sacra".into(),
            created_at: Utc::now(),
            status: EscalationStatus::Active,
            current_contact_idx: 1,
            notifications_sent: vec![],
            diagnosis_summary: "Container 'sacra-api' has been down for 15 minutes.".into(),
            suggested_actions: vec![
                "Check batch job memory usage".into(),
                "Increase memory limit".into(),
            ],
        };

        let msg = format_escalation_message(&esc, &sorted, false);
        assert!(msg.contains("ESCALATION"));
        assert!(msg.contains("sacra"));
        assert!(msg.contains("Container 'sacra-api'"));
        assert!(msg.contains("1. Check batch job memory usage"));
        assert!(msg.contains("2. Increase memory limit"));
        assert!(msg.contains("2/3")); // attempt 2 of 3
        assert!(msg.contains("Previously notified: Primary"));
        assert!(msg.contains("ack"));

        let repeat_msg = format_escalation_message(&esc, &sorted, true);
        assert!(repeat_msg.contains("REMINDER"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("esc.json");
        let mut mgr = EscalationManager::new(test_policy(), path.clone());

        let id = mgr
            .create("inc-1", "web", "it broke", &["fix it".into()])
            .id
            .clone();
        mgr.record_notification(&id, "Primary", "telegram", None)
            .unwrap();
        mgr.save().unwrap();

        let loaded = EscalationManager::load(&path).unwrap();
        let esc = loaded.get(&id).unwrap();
        assert_eq!(esc.incident_id, "inc-1");
        assert_eq!(esc.target_name, "web");
        assert_eq!(esc.diagnosis_summary, "it broke");
        assert_eq!(esc.suggested_actions, vec!["fix it"]);
        assert_eq!(esc.notifications_sent.len(), 1);
    }

    #[test]
    fn list_active_filters_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = EscalationManager::new(test_policy(), dir.path().join("esc.json"));

        let id1 = mgr.create("inc-1", "web1", "down", &[]).id.clone();
        let id2 = mgr.create("inc-2", "web2", "slow", &[]).id.clone();
        let _id3 = mgr.create("inc-3", "web3", "crash", &[]).id.clone();

        mgr.resolve(&id1, "bob", "fixed").unwrap();
        mgr.acknowledge(&id2, "alice").unwrap();

        let active = mgr.list_active();
        // id2 (acked) and id3 (active) should be in the list; id1 (resolved) should not.
        assert_eq!(active.len(), 2);
        assert!(active.iter().all(|e| e.incident_id != "inc-1"));
    }
}
