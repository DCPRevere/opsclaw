//! Approval gate for the `Approve` autonomy mode.
//!
//! Sends a notification asking for human approval before executing a runbook,
//! then waits for a response (or times out).
//!
//! When the notifier supports inline buttons (e.g. Telegram), the approval
//! request is sent with ✅ Approve / ❌ Reject buttons.  A file-based state
//! store under `~/.opsclaw/approvals/` bridges the button callback back to the
//! polling loop.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use super::notifier::{AlertNotifier, InlineButton};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
// File-based approval state
// ---------------------------------------------------------------------------

/// Directory under `~/.opsclaw` where approval state files live.
const APPROVALS_DIR: &str = "approvals";

/// Poll interval when checking for a callback response.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Returns `~/.opsclaw/approvals`.
pub fn approvals_dir() -> Result<PathBuf> {
    let home = directories::UserDirs::new()
        .context("Cannot determine home directory")?
        .home_dir()
        .to_path_buf();
    Ok(home.join(".opsclaw").join(APPROVALS_DIR))
}

/// Persist an approval request to `~/.opsclaw/approvals/{id}.json`.
pub async fn write_approval_state(req: &ApprovalRequest) -> Result<PathBuf> {
    let dir = approvals_dir()?;
    tokio::fs::create_dir_all(&dir).await?;
    let path = dir.join(format!("{}.json", req.id));
    let json = serde_json::to_string_pretty(req)?;
    tokio::fs::write(&path, json).await?;
    Ok(path)
}

/// Read an approval request from disk.
pub async fn read_approval_state(id: &str) -> Result<Option<ApprovalRequest>> {
    let path = approvals_dir()?.join(format!("{id}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let data = tokio::fs::read_to_string(&path).await?;
    let req: ApprovalRequest = serde_json::from_str(&data)?;
    Ok(Some(req))
}

/// Update the status of an approval on disk. Called by the callback handler
/// when a Telegram inline button is pressed.
pub async fn resolve_approval(id: &str, status: ApprovalStatus) -> Result<()> {
    let path = approvals_dir()?.join(format!("{id}.json"));
    let data = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("approval {id} not found on disk"))?;
    let mut req: ApprovalRequest = serde_json::from_str(&data)?;
    req.status = status;
    let json = serde_json::to_string_pretty(&req)?;
    tokio::fs::write(&path, json).await?;
    Ok(())
}

/// Parse callback_data from an inline button press.
///
/// Format: `approval:{id}:{action}` where action is `approve` or `reject`.
pub fn parse_callback_data(data: &str) -> Option<(String, ApprovalStatus)> {
    let parts: Vec<&str> = data.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "approval" {
        return None;
    }
    let id = parts[1].to_owned();
    let status = match parts[2] {
        "approve" => ApprovalStatus::Approved,
        "reject" => ApprovalStatus::Rejected,
        _ => return None,
    };
    Some((id, status))
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

/// Build the inline buttons for an approval request.
fn approval_buttons(request_id: &str) -> Vec<InlineButton> {
    vec![
        InlineButton::new("\u{2705} Approve", format!("approval:{request_id}:approve")),
        InlineButton::new("\u{274c} Reject", format!("approval:{request_id}:reject")),
    ]
}

/// Ask for human approval via the configured notifier.
///
/// Returns `true` if the action was approved, `false` if rejected or timed out.
///
/// When the notifier supports buttons the message is sent with an inline
/// keyboard. The function then polls the file-based approval state for a
/// response until `timeout_secs` elapses.
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

    // Persist the pending request so the callback handler can find it.
    if let Err(e) = write_approval_state(&req).await {
        warn!("Failed to persist approval state: {e}");
    }

    let buttons = approval_buttons(&req.id);
    let send_result = notifier
        .notify_with_buttons(target, &message, &buttons)
        .await;

    if let Err(e) = send_result {
        warn!("Failed to send approval notification: {e}");
        req.status = ApprovalStatus::Rejected;
        let _ = write_approval_state(&req).await;
        return Ok(false);
    }

    // Poll for a response on disk.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        if tokio::time::Instant::now() >= deadline {
            break;
        }

        if let Ok(Some(state)) = read_approval_state(&req.id).await {
            match state.status {
                ApprovalStatus::Approved => {
                    info!(id = %req.id, target, "Approval granted");
                    return Ok(true);
                }
                ApprovalStatus::Rejected => {
                    info!(id = %req.id, target, "Approval rejected");
                    return Ok(false);
                }
                _ => {} // still pending — keep polling
            }
        }
    }

    req.status = ApprovalStatus::TimedOut;
    let _ = write_approval_state(&req).await;
    info!(
        id = %req.id,
        target,
        "Approval request timed out after {timeout_secs}s — action denied"
    );

    Ok(false)
}

/// Handle a Telegram callback query for an approval button press.
///
/// Call this from the webhook/update handler when `callback_data` matches the
/// `approval:*` pattern. Returns a human-readable response string suitable for
/// `answerCallbackQuery`.
pub async fn handle_approval_callback(callback_data: &str) -> Result<String> {
    let (id, status) =
        parse_callback_data(callback_data).context("invalid approval callback data")?;

    let label = match &status {
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Rejected => "rejected",
        _ => "unknown",
    };

    resolve_approval(&id, status).await?;

    Ok(format!("Action {label}."))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    use crate::ops::notifier::{AlertNotifier, InlineButton};
    use crate::tools::monitoring::{Alert, HealthCheck};

    /// A notifier that records messages and buttons for assertions.
    struct RecordingNotifier {
        messages: tokio::sync::Mutex<Vec<String>>,
        buttons: tokio::sync::Mutex<Vec<Vec<InlineButton>>>,
    }

    impl RecordingNotifier {
        fn new() -> Self {
            Self {
                messages: tokio::sync::Mutex::new(Vec::new()),
                buttons: tokio::sync::Mutex::new(Vec::new()),
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
        async fn notify_with_buttons(
            &self,
            _target: &str,
            message: &str,
            buttons: &[InlineButton],
        ) -> anyhow::Result<()> {
            self.messages.lock().await.push(message.to_owned());
            self.buttons.lock().await.push(buttons.to_vec());
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

    #[tokio::test]
    async fn request_approval_sends_buttons() {
        let notifier = RecordingNotifier::new();

        let _ = request_approval(&notifier, "web-1", "restart nginx", 1)
            .await
            .unwrap();

        let btns = notifier.buttons.lock().await;
        assert_eq!(btns.len(), 1, "should have sent one set of buttons");
        assert_eq!(btns[0].len(), 2, "should have approve + reject buttons");
        assert!(btns[0][0].callback_data.contains(":approve"));
        assert!(btns[0][1].callback_data.contains(":reject"));
    }

    #[test]
    fn parse_callback_data_valid() {
        let (id, status) = parse_callback_data("approval:abc-123:approve").unwrap();
        assert_eq!(id, "abc-123");
        assert_eq!(status, ApprovalStatus::Approved);

        let (id, status) = parse_callback_data("approval:xyz:reject").unwrap();
        assert_eq!(id, "xyz");
        assert_eq!(status, ApprovalStatus::Rejected);
    }

    #[test]
    fn parse_callback_data_invalid() {
        assert!(parse_callback_data("bogus").is_none());
        assert!(parse_callback_data("approval:id:nope").is_none());
        assert!(parse_callback_data("other:id:approve").is_none());
    }

    #[tokio::test]
    async fn resolve_and_read_approval_state() {
        let req = ApprovalRequest::new("srv-1", "deploy v2");
        let path = write_approval_state(&req).await.unwrap();

        // Should be pending.
        let loaded = read_approval_state(&req.id).await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::Pending);

        // Resolve it.
        resolve_approval(&req.id, ApprovalStatus::Approved)
            .await
            .unwrap();
        let loaded = read_approval_state(&req.id).await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::Approved);

        // Cleanup.
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn handle_approval_callback_resolves() {
        let req = ApprovalRequest::new("srv-1", "restart");
        let path = write_approval_state(&req).await.unwrap();

        let data = format!("approval:{}:approve", req.id);
        let msg = handle_approval_callback(&data).await.unwrap();
        assert!(msg.contains("approved"));

        let loaded = read_approval_state(&req.id).await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::Approved);

        let _ = tokio::fs::remove_file(&path).await;
    }
}
