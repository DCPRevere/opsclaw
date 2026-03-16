use zeroclaw::ops::notifier::{
    format_alert, format_health_check, severity_meets_threshold, NullNotifier,
};
use zeroclaw::tools::monitoring::{Alert, AlertCategory, AlertSeverity, HealthCheck, HealthStatus};

use chrono::Utc;

// ---------------------------------------------------------------------------
// Message formatting
// ---------------------------------------------------------------------------

#[test]
fn format_critical_alert() {
    let alert = Alert {
        severity: AlertSeverity::Critical,
        category: AlertCategory::ContainerDown,
        message: "Container 'api' is DOWN".to_string(),
    };
    let text = format_alert("sacra", &alert);
    assert!(text.contains("CRITICAL"));
    assert!(text.contains("sacra"));
    assert!(text.contains("Container 'api' is DOWN"));
    assert!(text.contains("\u{1f6a8}"));
}

#[test]
fn format_warning_alert() {
    let alert = Alert {
        severity: AlertSeverity::Warning,
        category: AlertCategory::DiskSpaceLow,
        message: "Disk at 85%".to_string(),
    };
    let text = format_alert("prod-web", &alert);
    assert!(text.contains("WARNING"));
    assert!(text.contains("prod-web"));
    assert!(text.contains("Disk at 85%"));
}

#[test]
fn format_info_alert() {
    let alert = Alert {
        severity: AlertSeverity::Info,
        category: AlertCategory::NewPort,
        message: "New port 8080 detected".to_string(),
    };
    let text = format_alert("staging", &alert);
    assert!(text.contains("INFO"));
    assert!(text.contains("staging"));
}

#[test]
fn format_health_check_summary() {
    let alerts = [
        Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ContainerDown,
            message: "Container `sacra-api` is DOWN (was running)".to_string(),
        },
        Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::DiskSpaceLow,
            message: "Disk usage at 91% on / (threshold: 90%)".to_string(),
        },
    ];
    let refs: Vec<&Alert> = alerts.iter().collect();
    let text = format_health_check("sacra", &refs);

    assert!(text.contains("*sacra*"));
    assert!(text.contains("2 issues"));
    assert!(text.contains("sacra-api"));
    assert!(text.contains("91%"));
}

#[test]
fn format_health_check_single_issue() {
    let alerts = [Alert {
        severity: AlertSeverity::Warning,
        category: AlertCategory::HighLoad,
        message: "Load average 9.2".to_string(),
    }];
    let refs: Vec<&Alert> = alerts.iter().collect();
    let text = format_health_check("db-01", &refs);

    assert!(text.contains("1 issue"));
    assert!(!text.contains("issues"));
}

// ---------------------------------------------------------------------------
// NullNotifier
// ---------------------------------------------------------------------------

#[tokio::test]
async fn null_notifier_returns_ok() {
    use zeroclaw::ops::notifier::AlertNotifier;

    let notifier = NullNotifier;

    let alert = Alert {
        severity: AlertSeverity::Critical,
        category: AlertCategory::ContainerDown,
        message: "test".to_string(),
    };
    let result: anyhow::Result<()> = notifier.notify_alert("target", &alert).await;
    assert!(result.is_ok());

    let health = HealthCheck {
        target_name: "target".to_string(),
        checked_at: Utc::now(),
        status: HealthStatus::Healthy,
        alerts: vec![],
    };
    let result: anyhow::Result<()> = notifier.notify("target", &health).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Severity filtering
// ---------------------------------------------------------------------------

#[test]
fn severity_threshold_info_passes_all() {
    assert!(severity_meets_threshold(
        &AlertSeverity::Info,
        &AlertSeverity::Info
    ));
    assert!(severity_meets_threshold(
        &AlertSeverity::Warning,
        &AlertSeverity::Info
    ));
    assert!(severity_meets_threshold(
        &AlertSeverity::Critical,
        &AlertSeverity::Info
    ));
}

#[test]
fn severity_threshold_warning_filters_info() {
    assert!(!severity_meets_threshold(
        &AlertSeverity::Info,
        &AlertSeverity::Warning
    ));
    assert!(severity_meets_threshold(
        &AlertSeverity::Warning,
        &AlertSeverity::Warning
    ));
    assert!(severity_meets_threshold(
        &AlertSeverity::Critical,
        &AlertSeverity::Warning
    ));
}

#[test]
fn severity_threshold_critical_filters_info_and_warning() {
    assert!(!severity_meets_threshold(
        &AlertSeverity::Info,
        &AlertSeverity::Critical
    ));
    assert!(!severity_meets_threshold(
        &AlertSeverity::Warning,
        &AlertSeverity::Critical
    ));
    assert!(severity_meets_threshold(
        &AlertSeverity::Critical,
        &AlertSeverity::Critical
    ));
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_min_severity_variants() {
    use zeroclaw::config::schema::parse_min_severity;

    assert_eq!(parse_min_severity("info"), AlertSeverity::Info);
    assert_eq!(parse_min_severity("warning"), AlertSeverity::Warning);
    assert_eq!(parse_min_severity("critical"), AlertSeverity::Critical);
    assert_eq!(parse_min_severity("INFO"), AlertSeverity::Info);
    assert_eq!(parse_min_severity("CRITICAL"), AlertSeverity::Critical);
    // Unknown falls back to warning
    assert_eq!(parse_min_severity("unknown"), AlertSeverity::Warning);
}
