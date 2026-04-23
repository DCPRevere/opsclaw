//! Channel-agnostic approval abstractions.
//!
//! An `ApprovalChannel` represents one way to ask a human for approval —
//! Telegram buttons, Slack Block Kit, CLI stdin, email magic link, etc. Each
//! channel owns the full request → wait → response lifecycle for its transport.
//!
//! The dispatcher in `ops::approval::request_approval` takes a slice of channels
//! and returns on the first decisive outcome across all of them.

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;

use super::approval::ApprovalRequest;

/// The outcome of asking one channel for approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    Rejected,
    TimedOut,
    /// The channel could not deliver the request (network error, unconfigured,
    /// etc). The dispatcher treats this as non-decisive — other channels may
    /// still resolve.
    Failed(String),
}

impl ApprovalOutcome {
    /// `true` if this outcome should end the dispatcher's wait.
    pub fn is_decisive(&self) -> bool {
        matches!(self, Self::Approved | Self::Rejected)
    }
}

/// One transport-specific way to request human approval.
#[async_trait]
pub trait ApprovalChannel: Send + Sync {
    /// Short name for logs and audit entries (`"telegram"`, `"slack"`, `"cli"`).
    fn name(&self) -> &str;

    /// Send the request and wait for a response, or until `timeout` elapses.
    async fn request(
        &self,
        req: &ApprovalRequest,
        target: &str,
        timeout: Duration,
    ) -> Result<ApprovalOutcome>;
}
