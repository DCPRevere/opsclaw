//! Monitoring loop component tests (Phase 1f).
//!
//! Validates that health check cron jobs are created with the right
//! configuration — correct tool allowlists, isolated sessions, delivery
//! config, and system prompt construction.

use zeroclaw::config::Config;

// Import once implemented.
use zeroclaw::monitoring::{HealthCheckBuilder, MonitoringConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Health check cron job construction
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_check_creates_agent_job_type() {
    let check = HealthCheckBuilder::new("prod-web-1")
        .interval_minutes(5)
        .build();
    assert_eq!(
        check.job_type().as_str(),
        "agent",
        "health checks must be Agent jobs, not Shell"
    );
}

#[test]
fn health_check_uses_isolated_session() {
    let check = HealthCheckBuilder::new("prod-web-1")
        .interval_minutes(5)
        .build();
    assert_eq!(
        check.session_target().as_str(),
        "isolated",
        "health checks must use isolated sessions to avoid cross-contamination"
    );
}

#[test]
fn health_check_restricts_allowed_tools_ssh_target() {
    let check = HealthCheckBuilder::new("prod-web-1")
        .target_type("ssh")
        .interval_minutes(5)
        .build();
    let allowed = check.allowed_tools().expect("should have tool allowlist");
    assert!(allowed.contains(&"ssh".to_string()));
    assert!(allowed.contains(&"memory_recall".to_string()));
    assert!(allowed.contains(&"memory_store".to_string()));
    // Should NOT include destructive or unrelated tools.
    assert!(!allowed.contains(&"file_write".to_string()));
    assert!(!allowed.contains(&"shell".to_string()));
    assert!(!allowed.contains(&"browser".to_string()));
}

#[test]
fn health_check_restricts_allowed_tools_local_target() {
    let check = HealthCheckBuilder::new("this-box")
        .target_type("local")
        .interval_minutes(5)
        .build();
    let allowed = check.allowed_tools().expect("should have tool allowlist");
    // Local target uses shell instead of SSH, but still restricted.
    assert!(
        allowed.contains(&"shell".to_string()) || allowed.contains(&"local_exec".to_string()),
        "local target should allow local command execution"
    );
    assert!(allowed.contains(&"memory_recall".to_string()));
    assert!(allowed.contains(&"memory_store".to_string()));
}

// ─────────────────────────────────────────────────────────────────────────────
// System prompt construction
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_check_prompt_includes_target_name() {
    let check = HealthCheckBuilder::new("prod-web-1")
        .interval_minutes(5)
        .build();
    let prompt = check.system_prompt();
    assert!(
        prompt.contains("prod-web-1"),
        "prompt should reference the target by name"
    );
}

#[test]
fn health_check_prompt_includes_snapshot_context() {
    let snapshot_json = r#"{"containers": [{"name": "web", "image": "nginx"}]}"#;
    let check = HealthCheckBuilder::new("prod-web-1")
        .snapshot(snapshot_json)
        .interval_minutes(5)
        .build();
    let prompt = check.system_prompt();
    assert!(
        prompt.contains("nginx"),
        "prompt should include snapshot data so the LLM knows what to expect"
    );
}

#[test]
fn health_check_prompt_includes_user_context() {
    let context = "Postgres runs on port 5433. Redis is for sessions only.";
    let check = HealthCheckBuilder::new("prod-web-1")
        .context(context)
        .interval_minutes(5)
        .build();
    let prompt = check.system_prompt();
    assert!(
        prompt.contains("5433"),
        "prompt should include user-provided target context"
    );
    assert!(prompt.contains("sessions"));
}

#[test]
fn health_check_prompt_without_context_still_valid() {
    let check = HealthCheckBuilder::new("prod-web-1")
        .interval_minutes(5)
        .build();
    let prompt = check.system_prompt();
    assert!(!prompt.is_empty(), "prompt should still be valid without context");
    assert!(
        prompt.contains("prod-web-1"),
        "prompt should at minimum reference the target"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduling
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_check_default_interval_is_5_minutes() {
    let check = HealthCheckBuilder::new("prod-web-1").build();
    assert_eq!(
        check.interval_ms(),
        5 * 60 * 1000,
        "default interval should be 5 minutes"
    );
}

#[test]
fn health_check_custom_interval() {
    let check = HealthCheckBuilder::new("prod-web-1")
        .interval_minutes(1)
        .build();
    assert_eq!(check.interval_ms(), 60_000);
}

#[test]
fn health_check_interval_minimum_enforced() {
    // Checking more frequently than every 30 seconds is wasteful and expensive.
    let check = HealthCheckBuilder::new("prod-web-1")
        .interval_seconds(10)
        .build();
    assert!(
        check.interval_ms() >= 30_000,
        "interval should not be less than 30 seconds"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Delivery config
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_check_delivery_targets_configured_channel() {
    let check = HealthCheckBuilder::new("prod-web-1")
        .delivery_channel("telegram")
        .delivery_recipient("123456789")
        .interval_minutes(5)
        .build();
    let delivery = check.delivery();
    assert_eq!(delivery.channel, "telegram");
    assert_eq!(delivery.recipient, "123456789");
}

#[test]
fn health_check_delivery_defaults_to_none() {
    let check = HealthCheckBuilder::new("prod-web-1")
        .interval_minutes(5)
        .build();
    let delivery = check.delivery();
    assert!(
        delivery.channel.is_empty() || delivery.channel == "none",
        "without explicit delivery config, should default to none"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Config-driven creation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn monitoring_config_creates_one_check_per_target() {
    let toml_str = r#"
[[targets]]
name = "prod-web-1"
type = "ssh"
host = "203.0.113.10"
user = "opsclaw"
key = "/etc/opsclaw/keys/prod"
autonomy = "observe"

[[targets]]
name = "this-box"
type = "local"
autonomy = "observe"

[monitoring]
interval_minutes = 5
"#;
    let config: Config = toml::from_str(toml_str).expect("should parse");
    let checks = MonitoringConfig::from_config(&config).health_checks();
    assert_eq!(
        checks.len(),
        2,
        "should create one health check per target"
    );
    let names: Vec<&str> = checks.iter().map(|c| c.target_name()).collect();
    assert!(names.contains(&"prod-web-1"));
    assert!(names.contains(&"this-box"));
}
