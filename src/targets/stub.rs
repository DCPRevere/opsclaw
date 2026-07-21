//! Executors not yet implemented in this wave: `CloudExecutor` (azure via the
//! `az` CLI per `docs/plans/IMPLEMENTATION.md` §5) and a gVisor-sandboxed
//! executor (Tier 2 test harness target, `docs/DESIGN.md` §6). Both are
//! wired into `TargetKind`/config already (`domain::CloudProvider`,
//! `TargetKind::Cloud`), so the stub exists to keep the target registry
//! total over `TargetKind` rather than silently missing a match arm — every
//! call fails loud and explains why, never panics or fakes success.

use std::time::Duration;

use async_trait::async_trait;

use crate::Result;
use crate::error::Error;
use crate::targets::{Command, ExecOutput, ProbeReport, TargetExecutor};

/// Explains why a target type has no executor yet, without ever pretending
/// to succeed. Every method returns `Err` — there is no fake-success path
/// (this is not a fakes-mode double; it is "not built").
pub struct NotImplementedExecutor {
    what: &'static str,
}

impl NotImplementedExecutor {
    /// `CloudExecutor` (azure via `az` CLI) — provider-pluggable per
    /// `docs/DESIGN.md` §4 ("Azure must be a provider, not the
    /// architecture"); only the azure shape is stubbed here since that's the
    /// only cloud provider config accepts today (`CloudProvider::Azure`).
    pub fn cloud() -> Self {
        NotImplementedExecutor {
            what: "cloud (az CLI) executor is not implemented yet — target configured but unusable",
        }
    }

    /// gVisor-sandboxed executor for the Tier 2 acceptance harness
    /// (`docs/DESIGN.md` §6) — a later wave.
    pub fn gvisor() -> Self {
        NotImplementedExecutor {
            what: "gVisor executor is not implemented yet (Tier 2 harness target)",
        }
    }
}

#[async_trait]
impl TargetExecutor for NotImplementedExecutor {
    async fn run(&self, _cmd: &Command, _timeout: Duration) -> Result<ExecOutput> {
        Err(Error::other(self.what))
    }

    async fn probe(&self) -> Result<ProbeReport> {
        Ok(ProbeReport { reachable: false, detail: self.what.to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cloud_stub_explains_itself_on_run_and_probe() {
        let exec = NotImplementedExecutor::cloud();
        let cmd = Command {
            target: crate::domain::FqTarget::new("p", "e", "azure-vm"),
            line: "az vm list".to_string(),
        };
        let err = exec.run(&cmd, Duration::from_secs(1)).await.unwrap_err();
        assert!(err.to_string().contains("cloud"));

        let probe = exec.probe().await.unwrap();
        assert!(!probe.reachable);
    }

    #[tokio::test]
    async fn gvisor_stub_explains_itself() {
        let exec = NotImplementedExecutor::gvisor();
        let probe = exec.probe().await.unwrap();
        assert!(!probe.reachable);
        assert!(probe.detail.contains("gVisor"));
    }
}
