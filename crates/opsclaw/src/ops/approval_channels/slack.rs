//! Slack `ApprovalChannel` — adapter over `zeroclaw_api::channel::Channel`.
//!
//! Mirrors `TelegramApprovalChannel`. Upstream `SlackChannel` inherits the
//! default `request_approval` impl from the `Channel` trait, which returns
//! `None` — so today this adapter always reports `Failed("...")`. When upstream
//! wires up Block Kit interactivity for Slack, this adapter starts working with
//! no changes here.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use zeroclaw_api::channel::{Channel, ChannelApprovalRequest, ChannelApprovalResponse};

use crate::ops::approval::ApprovalRequest;
use crate::ops::approval_channel::{ApprovalChannel, ApprovalOutcome};

pub struct SlackApprovalChannel {
    channel: Arc<dyn Channel>,
    /// Slack channel ID (or `channel_id:thread_ts`) to post the prompt to.
    recipient: String,
}

impl SlackApprovalChannel {
    pub fn new(channel: Arc<dyn Channel>, recipient: String) -> Self {
        Self { channel, recipient }
    }
}

#[async_trait]
impl ApprovalChannel for SlackApprovalChannel {
    fn name(&self) -> &str {
        "slack"
    }

    async fn request(
        &self,
        req: &ApprovalRequest,
        _target: &str,
        _timeout: Duration,
    ) -> Result<ApprovalOutcome> {
        let upstream_req = ChannelApprovalRequest {
            tool_name: req.target.clone(),
            arguments_summary: req.action_description.clone(),
        };

        match self.channel.request_approval(&self.recipient, &upstream_req).await {
            Ok(Some(ChannelApprovalResponse::Approve))
            | Ok(Some(ChannelApprovalResponse::AlwaysApprove)) => Ok(ApprovalOutcome::Approved),
            Ok(Some(ChannelApprovalResponse::Deny)) => Ok(ApprovalOutcome::Rejected),
            Ok(None) => Ok(ApprovalOutcome::Failed(
                "slack channel does not yet implement interactive approval upstream".into(),
            )),
            Err(e) => Ok(ApprovalOutcome::Failed(format!("upstream error: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use zeroclaw_api::channel::{ChannelMessage, SendMessage};

    struct FakeChannel {
        response: Option<ChannelApprovalResponse>,
    }

    #[async_trait]
    impl Channel for FakeChannel {
        fn name(&self) -> &str {
            "fake-slack"
        }
        async fn send(&self, _msg: &SendMessage) -> anyhow::Result<()> {
            Ok(())
        }
        async fn listen(
            &self,
            _tx: tokio::sync::mpsc::Sender<ChannelMessage>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn request_approval(
            &self,
            _recipient: &str,
            _request: &ChannelApprovalRequest,
        ) -> anyhow::Result<Option<ChannelApprovalResponse>> {
            Ok(self.response)
        }
    }

    #[tokio::test]
    async fn upstream_none_reports_failed_today() {
        // Default Channel impl (what upstream SlackChannel has today) returns None.
        let ch = SlackApprovalChannel::new(
            Arc::new(FakeChannel { response: None }),
            "C123".into(),
        );
        let req = ApprovalRequest::new("web-1", "restart");
        match ch.request(&req, "web-1", Duration::from_secs(1)).await.unwrap() {
            ApprovalOutcome::Failed(msg) => assert!(msg.contains("slack")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upstream_approve_once_implemented_maps_to_approved() {
        let ch = SlackApprovalChannel::new(
            Arc::new(FakeChannel {
                response: Some(ChannelApprovalResponse::Approve),
            }),
            "C123".into(),
        );
        let req = ApprovalRequest::new("web-1", "restart");
        let out = ch.request(&req, "web-1", Duration::from_secs(1)).await.unwrap();
        assert_eq!(out, ApprovalOutcome::Approved);
    }

    #[tokio::test]
    async fn upstream_deny_maps_to_rejected() {
        let ch = SlackApprovalChannel::new(
            Arc::new(FakeChannel {
                response: Some(ChannelApprovalResponse::Deny),
            }),
            "C123".into(),
        );
        let req = ApprovalRequest::new("web-1", "restart");
        let out = ch.request(&req, "web-1", Duration::from_secs(1)).await.unwrap();
        assert_eq!(out, ApprovalOutcome::Rejected);
    }
}
