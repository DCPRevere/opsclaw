//! CLI `ApprovalChannel` — stdin prompt via zeroclaw's `ApprovalManager`.
//!
//! This is where opsclaw reuses zeroclaw's approval code: the runtime already
//! owns the "prompt on stdin, parse Y/N/A" logic and its audit trail, so the
//! CLI channel just delegates.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use zeroclaw_runtime::approval::{
    ApprovalManager, ApprovalRequest as RuntimeApprovalRequest, ApprovalResponse,
};

use crate::ops::approval::ApprovalRequest;
use crate::ops::approval_channel::{ApprovalChannel, ApprovalOutcome};

pub struct CliApprovalChannel {
    manager: Arc<ApprovalManager>,
}

impl CliApprovalChannel {
    pub fn new(manager: Arc<ApprovalManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl ApprovalChannel for CliApprovalChannel {
    fn name(&self) -> &str {
        "cli"
    }

    async fn request(
        &self,
        req: &ApprovalRequest,
        _target: &str,
        _timeout: Duration,
    ) -> Result<ApprovalOutcome> {
        // prompt_cli is synchronous (blocks on stdin) — hop to a blocking thread
        // so we don't stall the runtime.
        let runtime_req = RuntimeApprovalRequest {
            tool_name: req.target.clone(),
            arguments: serde_json::json!({ "action": req.action_description }),
        };
        let manager = Arc::clone(&self.manager);
        let response = tokio::task::spawn_blocking(move || manager.prompt_cli(&runtime_req))
            .await
            .map_err(|e| anyhow::anyhow!("prompt_cli task join: {e}"))?;

        Ok(match response {
            ApprovalResponse::Yes | ApprovalResponse::Always => ApprovalOutcome::Approved,
            ApprovalResponse::No => ApprovalOutcome::Rejected,
        })
    }
}
