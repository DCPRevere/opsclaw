//! Approval gate for the `Approve` autonomy mode.
//!
//! Sends a notification asking for human approval before executing a runbook,
//! then waits for a response (or times out).

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use super::notifier::AlertNotifier;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub target: String,
    pub action_description: String,
    pub created_at: DateTime<Utc>,
    pub status: ApprovalStatus,
}

impl ApprovalRequest {
    pub fn new(target: &str, action_description: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            target: target.to_owned(),
            action_description: action_description.to_owned(),
            created_at: Utc::now(),
            status: ApprovalStatus::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

/// Ask for human approval via the configured notifier.
///
/// Returns `true` if the action was approved, `false` if rejected or timed out.
///
/// **Current limitation:** reply handling is not yet implemented — the function
/// always times out after `timeout_secs` and returns `false`.
pub async fn request_approval(
    notifier: &dyn AlertNotifier,
    target: &str,
    action: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let mut req = ApprovalRequest::new(target, action);

    let message = format!(
        "\u{1f510} OpsClaw wants to execute on {target}: {action}\n\
         Reply APPROVE or REJECT within {timeout_secs}s"
    );

    info!(
        id = %req.id,
        target,
        action,
        "Sending approval request"
    );

    if let Err(e) = notifier.notify_text(target, &message).await {
        warn!("Failed to send approval notification: {e}");
        // If we can't even notify, treat as denied.
        req.status = ApprovalStatus::Rejected;
        return Ok(false);
    }

    // TODO: poll for reply (e.g. via Telegram getUpdates or a webhook callback).
    // For now we simply wait for the timeout and deny.
    tokio::time::sleep(std::time::Duration::from_secs(timeout_secs)).await;

    req.status = ApprovalStatus::TimedOut;
    info!(
        id = %req.id,
        target,
        "Approval request timed out after {timeout_secs}s — action denied"
    );

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    use crate::ops::notifier::AlertNotifier;
    use crate::tools::monitoring::{Alert, HealthCheck};

    /// A notifier that records messages for assertions.
    struct RecordingNotifier {
        messages: tokio::sync::Mutex<Vec<String>>,
    }

    impl RecordingNotifier {
        fn new() -> Self {
            Self {
                messages: tokio::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl AlertNotifier for RecordingNotifier {
        async fn notify_alert(&self, _target: &str, _alert: &Alert) -> anyhow::Result<()> {
            Ok(())
        }
        async fn notify(&self, _target: &str, _health: &HealthCheck) -> anyhow::Result<()> {
            Ok(())
        }
        async fn notify_text(&self, _target: &str, message: &str) -> anyhow::Result<()> {
            self.messages.lock().await.push(message.to_owned());
            Ok(())
        }
    }

    #[tokio::test]
    async fn request_approval_times_out_and_returns_false() {
        let notifier = RecordingNotifier::new();

        let result = request_approval(&notifier, "web-1", "restart nginx", 1)
            .await
            .unwrap();

        assert!(!result, "should deny when timed out");
        let msgs = notifier.messages.lock().await;
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("web-1"));
        assert!(msgs[0].contains("restart nginx"));
    }
}
