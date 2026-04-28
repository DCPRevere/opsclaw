//! Telegram `ApprovalChannel` — thin adapter over the upstream
//! `zeroclaw_api::channel::Channel::request_approval` trait method.
//!
//! The upstream `TelegramChannel` in `zeroclaw-channels` already owns the
//! inline-keyboard prompt, in-memory `oneshot` registry, webhook routing, and
//! timeout logic. This adapter just forwards the opsclaw `ApprovalRequest`
//! across that interface and maps the response into an `ApprovalOutcome`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use zeroclaw_api::channel::{Channel, ChannelApprovalRequest, ChannelApprovalResponse};

use crate::ops::approval::ApprovalRequest;
use crate::ops::approval_channel::{ApprovalChannel, ApprovalOutcome};

pub struct TelegramApprovalChannel {
    channel: Arc<dyn Channel>,
    /// Telegram chat id (or `chat_id:thread_id`) to send the prompt to.
    recipient: String,
}

impl TelegramApprovalChannel {
    pub fn new(channel: Arc<dyn Channel>, recipient: String) -> Self {
        Self { channel, recipient }
    }
}

#[async_trait]
impl ApprovalChannel for TelegramApprovalChannel {
    fn name(&self) -> &str {
        "telegram"
    }

    async fn request(
        &self,
        req: &ApprovalRequest,
        _target: &str,
        _timeout: Duration,
    ) -> Result<ApprovalOutcome> {
        // The upstream channel owns the timeout (`channels.telegram.approval_timeout_secs`).
        // We don't second-guess it; the dispatcher's per-call timeout still
        // bounds the whole `request_approval` call anyway.
        let upstream_req = ChannelApprovalRequest {
            tool_name: req.target.clone(),
            arguments_summary: req.action_description.clone(),
        };

        match self
            .channel
            .request_approval(&self.recipient, &upstream_req)
            .await
        {
            Ok(Some(ChannelApprovalResponse::Approve))
            | Ok(Some(ChannelApprovalResponse::AlwaysApprove)) => Ok(ApprovalOutcome::Approved),
            Ok(Some(ChannelApprovalResponse::Deny)) => Ok(ApprovalOutcome::Rejected),
            Ok(None) => Ok(ApprovalOutcome::Failed(
                "channel does not support interactive approval".into(),
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

    /// Fake `Channel` whose `request_approval` returns a preconfigured outcome.
    struct FakeChannel {
        response: Option<ChannelApprovalResponse>,
        error: bool,
    }

    #[async_trait]
    impl Channel for FakeChannel {
        fn name(&self) -> &str {
            "fake"
        }
        async fn send(&self, _message: &SendMessage) -> anyhow::Result<()> {
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
            if self.error {
                anyhow::bail!("fake upstream failure");
            }
            Ok(self.response)
        }
    }

    fn adapter(response: Option<ChannelApprovalResponse>) -> TelegramApprovalChannel {
        TelegramApprovalChannel::new(
            Arc::new(FakeChannel {
                response,
                error: false,
            }),
            "chat-123".into(),
        )
    }

    fn erroring_adapter() -> TelegramApprovalChannel {
        TelegramApprovalChannel::new(
            Arc::new(FakeChannel {
                response: None,
                error: true,
            }),
            "chat-123".into(),
        )
    }

    #[tokio::test]
    async fn approve_maps_to_approved() {
        let ch = adapter(Some(ChannelApprovalResponse::Approve));
        let req = ApprovalRequest::new("web-1", "restart");
        let out = ch
            .request(&req, "web-1", Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(out, ApprovalOutcome::Approved);
    }

    #[tokio::test]
    async fn always_approve_maps_to_approved() {
        let ch = adapter(Some(ChannelApprovalResponse::AlwaysApprove));
        let req = ApprovalRequest::new("web-1", "restart");
        let out = ch
            .request(&req, "web-1", Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(out, ApprovalOutcome::Approved);
    }

    #[tokio::test]
    async fn deny_maps_to_rejected() {
        let ch = adapter(Some(ChannelApprovalResponse::Deny));
        let req = ApprovalRequest::new("web-1", "restart");
        let out = ch
            .request(&req, "web-1", Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(out, ApprovalOutcome::Rejected);
    }

    #[tokio::test]
    async fn none_response_maps_to_failed() {
        let ch = adapter(None);
        let req = ApprovalRequest::new("web-1", "restart");
        match ch
            .request(&req, "web-1", Duration::from_secs(1))
            .await
            .unwrap()
        {
            ApprovalOutcome::Failed(msg) => assert!(msg.contains("does not support")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upstream_error_maps_to_failed() {
        let ch = erroring_adapter();
        let req = ApprovalRequest::new("web-1", "restart");
        match ch
            .request(&req, "web-1", Duration::from_secs(1))
            .await
            .unwrap()
        {
            ApprovalOutcome::Failed(msg) => assert!(msg.contains("upstream error")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
