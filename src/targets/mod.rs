//! Target executors: one connection/execution path per target type.
//!
//! Tools own vocabulary, never transport — the ONLY caller of
//! [`TargetExecutor::run`] is `policy::Policy::execute`, which classifies,
//! gates, and audits around it. Executor implementations land in Wave 2
//! (local → ssh (jump-host capable) → kubernetes → cloud/azure).

pub mod endpoint;
pub mod kubernetes;
pub mod local;
pub mod ssh;
pub mod stub;

pub use endpoint::EndpointExecutor;
pub use kubernetes::{KubernetesExecutor, KubernetesParams};
pub use local::LocalExecutor;
pub use ssh::{SshExecutor, SshParams};
pub use stub::NotImplementedExecutor;

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::domain::FqTarget;

/// A concrete command bound for a target. `line` is the exact string the risk
/// classifier pattern-matches and the audit log records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub target: FqTarget,
    pub line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

impl ExecOutput {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Connectivity/diagnostic probe result, used by `doctor` and target
/// expected-state checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub reachable: bool,
    pub detail: String,
}

/// One executor per configured target. Constructed with a resolved credential
/// (which must already be registered with the output scrubber).
#[async_trait]
pub trait TargetExecutor: Send + Sync {
    /// Run one command. Implementations do transport only — no policy, no
    /// audit, no retries with side effects.
    async fn run(&self, cmd: &Command, timeout: Duration) -> Result<ExecOutput>;

    /// Cheap connectivity probe (no side effects).
    async fn probe(&self) -> Result<ProbeReport>;
}
