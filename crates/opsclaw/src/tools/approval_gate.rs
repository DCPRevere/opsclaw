use crate::ops_config::OpsClawAutonomy;

/// Shared fail-closed autonomy gate for OpsClaw mutating tool actions.
pub fn mutating_action_block_reason(autonomy: OpsClawAutonomy) -> Option<&'static str> {
    match autonomy {
        OpsClawAutonomy::DryRun => Some("dry-run mode: mutating action rejected"),
        OpsClawAutonomy::Approve => {
            Some("approve mode: mutating action requires a server-side approval grant")
        }
        OpsClawAutonomy::Auto => None,
    }
}
