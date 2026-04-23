//! Approval gate for the `Approve` autonomy mode.
//!
//! Runbook execution pauses here until a human approves on one of the
//! configured channels (Telegram buttons, Slack Block Kit, CLI stdin, …). The
//! dispatcher fans the request out across all channels and returns on the
//! first decisive response; if every channel times out or fails, the action is
//! denied.
//!
//! Transport-specific logic lives in `ops::approval_channels::*`. This module
//! owns the shared data types and the dispatcher.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use futures_util::{future::FutureExt, stream::FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::openshell::{self, OpenShellContext};
use crate::ops::approval_channel::{ApprovalChannel, ApprovalOutcome};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// What a channel is being asked to approve. Passed by reference to each
/// `ApprovalChannel::request` call so the transport can format a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub target: String,
    pub action_description: String,
}

impl ApprovalRequest {
    pub fn new(target: &str, action_description: &str) -> Self {
        Self {
            target: target.to_owned(),
            action_description: action_description.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Ask for human approval across all configured channels.
///
/// Returns `true` on the first `Approved` response, `false` as soon as any
/// channel returns `Rejected` (reject wins — safer default for a policy gate),
/// and `false` if every channel times out or fails.
///
/// When OpenShell is active the policy engine is consulted first; a policy
/// denial short-circuits without touching any channel.
pub async fn request_approval(
    channels: &[Arc<dyn ApprovalChannel>],
    target: &str,
    action: &str,
    timeout_secs: u64,
    openshell_ctx: &OpenShellContext,
) -> Result<bool> {
    if openshell_ctx.is_active() {
        let allowed = openshell::policy::check_policy(openshell_ctx, action, target).await?;
        if !allowed {
            warn!("OpenShell policy denied: {action} on {target}");
            return Ok(false);
        }
        openshell::audit::emit_audit_event(
            openshell_ctx,
            &openshell::audit::AuditEvent {
                timestamp: Utc::now().to_rfc3339(),
                action: action.to_owned(),
                target: target.to_owned(),
                outcome: "approved".into(),
                details: serde_json::json!({"stage": "policy_check"}),
            },
        )
        .await;
    }

    if channels.is_empty() {
        warn!("No approval channels configured — denying action");
        return Ok(false);
    }

    let req = ApprovalRequest::new(target, action);
    let timeout = Duration::from_secs(timeout_secs);

    info!(
        target,
        action,
        channels = channels.len(),
        "Dispatching approval request"
    );

    let mut pending: FuturesUnordered<_> = channels
        .iter()
        .map(|channel| {
            let channel = Arc::clone(channel);
            let req = req.clone();
            let target = target.to_owned();
            async move {
                let outcome = channel.request(&req, &target, timeout).await;
                (channel.name().to_owned(), outcome)
            }
            .boxed()
        })
        .collect();

    while let Some((name, outcome)) = pending.next().await {
        match outcome {
            Ok(ApprovalOutcome::Approved) => {
                info!(target, channel = %name, "Approval granted");
                return Ok(true);
            }
            Ok(ApprovalOutcome::Rejected) => {
                info!(target, channel = %name, "Approval rejected");
                return Ok(false);
            }
            Ok(ApprovalOutcome::TimedOut) => {
                info!(target, channel = %name, "Channel timed out");
            }
            Ok(ApprovalOutcome::Failed(msg)) => {
                warn!(target, channel = %name, "Channel failed: {msg}");
            }
            Err(e) => {
                warn!(target, channel = %name, "Channel errored: {e}");
            }
        }
    }

    info!(
        target,
        "All channels exhausted without approval — action denied"
    );
    Ok(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::approval_channel::ApprovalOutcome;
    use async_trait::async_trait;

    fn inactive_openshell() -> OpenShellContext {
        OpenShellContext {
            active: false,
            sandbox_id: None,
            policy_endpoint: None,
            audit_endpoint: None,
        }
    }

    /// Test channel that returns a preset outcome after a configured delay.
    struct ScriptedChannel {
        label: &'static str,
        delay: Duration,
        outcome: ApprovalOutcome,
    }

    #[async_trait]
    impl ApprovalChannel for ScriptedChannel {
        fn name(&self) -> &str {
            self.label
        }
        async fn request(
            &self,
            _req: &ApprovalRequest,
            _target: &str,
            _timeout: Duration,
        ) -> Result<ApprovalOutcome> {
            tokio::time::sleep(self.delay).await;
            Ok(self.outcome.clone())
        }
    }

    #[tokio::test]
    async fn first_approval_wins_and_short_circuits() {
        let fast = Arc::new(ScriptedChannel {
            label: "fast",
            delay: Duration::from_millis(10),
            outcome: ApprovalOutcome::Approved,
        });
        let slow = Arc::new(ScriptedChannel {
            label: "slow",
            delay: Duration::from_secs(60),
            outcome: ApprovalOutcome::Rejected,
        });

        let channels: Vec<Arc<dyn ApprovalChannel>> = vec![fast, slow];
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            request_approval(&channels, "web-1", "restart", 30, &inactive_openshell()),
        )
        .await
        .expect("dispatcher must return before slow channel finishes")
        .unwrap();

        assert!(result, "fast approval should win");
    }

    #[tokio::test]
    async fn rejection_denies_immediately() {
        let fast = Arc::new(ScriptedChannel {
            label: "fast",
            delay: Duration::from_millis(10),
            outcome: ApprovalOutcome::Rejected,
        });
        let slow = Arc::new(ScriptedChannel {
            label: "slow",
            delay: Duration::from_secs(60),
            outcome: ApprovalOutcome::Approved,
        });

        let channels: Vec<Arc<dyn ApprovalChannel>> = vec![fast, slow];
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            request_approval(&channels, "web-1", "restart", 30, &inactive_openshell()),
        )
        .await
        .expect("dispatcher must return before slow channel finishes")
        .unwrap();

        assert!(!result, "first rejection should deny");
    }

    #[tokio::test]
    async fn all_timeouts_deny() {
        let a = Arc::new(ScriptedChannel {
            label: "a",
            delay: Duration::from_millis(5),
            outcome: ApprovalOutcome::TimedOut,
        });
        let b = Arc::new(ScriptedChannel {
            label: "b",
            delay: Duration::from_millis(10),
            outcome: ApprovalOutcome::TimedOut,
        });
        let channels: Vec<Arc<dyn ApprovalChannel>> = vec![a, b];
        let result = request_approval(&channels, "web-1", "restart", 1, &inactive_openshell())
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn failed_channels_do_not_block_approval() {
        let broken = Arc::new(ScriptedChannel {
            label: "broken",
            delay: Duration::from_millis(5),
            outcome: ApprovalOutcome::Failed("oops".into()),
        });
        let ok = Arc::new(ScriptedChannel {
            label: "ok",
            delay: Duration::from_millis(20),
            outcome: ApprovalOutcome::Approved,
        });
        let channels: Vec<Arc<dyn ApprovalChannel>> = vec![broken, ok];
        let result = request_approval(&channels, "web-1", "restart", 1, &inactive_openshell())
            .await
            .unwrap();
        assert!(result, "approval on a later channel must still win");
    }

    #[tokio::test]
    async fn no_channels_denies() {
        let channels: Vec<Arc<dyn ApprovalChannel>> = vec![];
        let result = request_approval(&channels, "web-1", "restart", 1, &inactive_openshell())
            .await
            .unwrap();
        assert!(!result);
    }
}
