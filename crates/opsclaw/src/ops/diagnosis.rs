//! Diagnosis data types — used by [`super::incident_search`] to read incident
//! JSONL files.

use crate::tools::monitoring::HealthStatus;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnosis {
    pub incident_id: String,
    pub target_name: String,
    pub timestamp: DateTime<Utc>,
    pub health_status: HealthStatus,
    pub alerts_summary: String,
    pub llm_assessment: String,
    pub suggested_actions: Vec<String>,
    pub severity: DiagnosisSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosisSeverity {
    Monitor,
    Investigate,
    Act,
}

impl std::fmt::Display for DiagnosisSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor => write!(f, "Monitor"),
            Self::Investigate => write!(f, "Investigate"),
            Self::Act => write!(f, "Act"),
        }
    }
}
