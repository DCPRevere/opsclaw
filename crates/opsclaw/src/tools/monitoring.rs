//! Monitoring data types used across OpsClaw modules.
//!
//! These types are retained for compatibility with the notification, probe,
//! escalation, and incident modules. The diff engine that previously lived here
//! has been removed — the agent interprets system state directly.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub target_name: String,
    pub checked_at: DateTime<Utc>,
    pub status: HealthStatus,
    pub alerts: Vec<Alert>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub message: String,
}

pub use crate::ops_config::AlertSeverity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertCategory {
    ContainerDown,
    ContainerRestarted,
    ServiceStopped,
    DiskSpaceLow,
    HighMemory,
    HighLoad,
    PortGone,
    NewPort,
    NewContainer,
    PodCrashLoop,
    PodNotReady,
    PodPending,
    DeploymentDegraded,
    NodeNotReady,
    PodHighRestarts,
    ProbeFailure,
    TlsCertExpiring,
    DnsResolutionFailed,
    MetricAnomaly,
}
