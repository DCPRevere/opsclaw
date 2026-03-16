//! Target config schema tests (Phase 1a).
//!
//! Validates parsing, validation, and defaults for the `[[targets]]` config
//! section. These tests define the contract before the implementation exists.

use zeroclaw::config::Config;

// ─────────────────────────────────────────────────────────────────────────────
// SSH target parsing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn target_ssh_parses_all_fields() {
    let toml_str = r#"
[[targets]]
name = "prod-web-1"
type = "ssh"
host = "203.0.113.10"
user = "opsclaw"
key = "/etc/opsclaw/keys/prod-web-1"
autonomy = "observe"
context_file = "context/prod-web-1.md"
"#;
    let config: Config = toml::from_str(toml_str).expect("valid SSH target should parse");
    let targets = config.targets.expect("targets should be present");
    assert_eq!(targets.len(), 1);
    let t = &targets[0];
    assert_eq!(t.name, "prod-web-1");
    assert_eq!(t.target_type, "ssh");
    assert_eq!(t.host.as_deref(), Some("203.0.113.10"));
    assert_eq!(t.user.as_deref(), Some("opsclaw"));
    assert_eq!(t.key.as_deref(), Some("/etc/opsclaw/keys/prod-web-1"));
    assert_eq!(t.autonomy, "observe");
    assert_eq!(t.context_file.as_deref(), Some("context/prod-web-1.md"));
}

#[test]
fn target_ssh_requires_host() {
    let toml_str = r#"
[[targets]]
name = "missing-host"
type = "ssh"
user = "opsclaw"
key = "/etc/opsclaw/keys/missing"
"#;
    let config: Config = toml::from_str(toml_str).expect("should parse");
    let targets = config.targets.expect("targets should be present");
    let t = &targets[0];
    // An SSH target without a host should fail validation (not parsing).
    assert!(
        t.validate().is_err(),
        "SSH target without host should fail validation"
    );
}

#[test]
fn target_ssh_requires_user() {
    let toml_str = r#"
[[targets]]
name = "missing-user"
type = "ssh"
host = "203.0.113.10"
key = "/etc/opsclaw/keys/missing"
"#;
    let config: Config = toml::from_str(toml_str).expect("should parse");
    let targets = config.targets.expect("targets should be present");
    let t = &targets[0];
    assert!(
        t.validate().is_err(),
        "SSH target without user should fail validation"
    );
}

#[test]
fn target_ssh_requires_key() {
    let toml_str = r#"
[[targets]]
name = "missing-key"
type = "ssh"
host = "203.0.113.10"
user = "opsclaw"
"#;
    let config: Config = toml::from_str(toml_str).expect("should parse");
    let targets = config.targets.expect("targets should be present");
    let t = &targets[0];
    assert!(
        t.validate().is_err(),
        "SSH target without key should fail validation"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Local target parsing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn target_local_parses_minimal_config() {
    let toml_str = r#"
[[targets]]
name = "this-box"
type = "local"
autonomy = "observe"
"#;
    let config: Config = toml::from_str(toml_str).expect("valid local target should parse");
    let targets = config.targets.expect("targets should be present");
    assert_eq!(targets.len(), 1);
    let t = &targets[0];
    assert_eq!(t.name, "this-box");
    assert_eq!(t.target_type, "local");
    assert!(t.host.is_none(), "local target should not require host");
    assert!(t.user.is_none(), "local target should not require user");
    assert!(t.key.is_none(), "local target should not require key");
}

#[test]
fn target_local_ignores_ssh_fields() {
    let toml_str = r#"
[[targets]]
name = "this-box"
type = "local"
host = "ignored"
user = "ignored"
key = "/ignored"
autonomy = "observe"
"#;
    let config: Config = toml::from_str(toml_str).expect("should parse even with extra fields");
    let targets = config.targets.expect("targets should be present");
    let t = &targets[0];
    assert_eq!(t.target_type, "local");
    assert!(
        t.validate().is_ok(),
        "local target should validate even with SSH fields present"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Multiple targets
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn target_multiple_targets_parse() {
    let toml_str = r#"
[[targets]]
name = "prod-web-1"
type = "ssh"
host = "203.0.113.10"
user = "opsclaw"
key = "/etc/opsclaw/keys/prod-web-1"
autonomy = "observe"

[[targets]]
name = "this-box"
type = "local"
autonomy = "suggest"
"#;
    let config: Config = toml::from_str(toml_str).expect("multiple targets should parse");
    let targets = config.targets.expect("targets should be present");
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].name, "prod-web-1");
    assert_eq!(targets[1].name, "this-box");
}

#[test]
fn target_duplicate_names_rejected() {
    let toml_str = r#"
[[targets]]
name = "prod"
type = "local"

[[targets]]
name = "prod"
type = "local"
"#;
    let config: Config = toml::from_str(toml_str).expect("should parse");
    let targets = config.targets.expect("targets should be present");
    // Duplicate names should fail at validation, not parse time.
    let names: Vec<&str> = targets.iter().map(|t| t.name.as_str()).collect();
    let mut deduped = names.clone();
    deduped.sort();
    deduped.dedup();
    assert_ne!(
        names.len(),
        deduped.len(),
        "test setup: confirm duplicates exist"
    );
    // The actual validation call:
    assert!(
        zeroclaw::config::validate_targets(&targets).is_err(),
        "duplicate target names should fail validation"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Autonomy levels
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn target_autonomy_defaults_to_observe() {
    let toml_str = r#"
[[targets]]
name = "no-autonomy-set"
type = "local"
"#;
    let config: Config = toml::from_str(toml_str).expect("should parse without autonomy");
    let targets = config.targets.expect("targets should be present");
    assert_eq!(
        targets[0].autonomy, "observe",
        "default autonomy should be observe (safest)"
    );
}

#[test]
fn target_autonomy_accepts_all_valid_levels() {
    for level in &["observe", "suggest", "act_on_known", "full_auto"] {
        let toml_str = format!(
            r#"
[[targets]]
name = "test"
type = "local"
autonomy = "{level}"
"#
        );
        let config: Config =
            toml::from_str(&toml_str).unwrap_or_else(|_| panic!("{level} should be valid"));
        let targets = config.targets.expect("targets should be present");
        assert_eq!(targets[0].autonomy, *level);
    }
}

#[test]
fn target_autonomy_rejects_invalid_level() {
    let toml_str = r#"
[[targets]]
name = "test"
type = "local"
autonomy = "yolo"
"#;
    let result: Result<Config, _> = toml::from_str(toml_str);
    assert!(
        result.is_err(),
        "invalid autonomy level should fail to parse"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Target type validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn target_unknown_type_rejected() {
    let toml_str = r#"
[[targets]]
name = "test"
type = "magic"
"#;
    let result: Result<Config, _> = toml::from_str(toml_str);
    assert!(
        result.is_err(),
        "unknown target type should fail to parse"
    );
}

#[test]
fn target_name_required() {
    let toml_str = r#"
[[targets]]
type = "local"
"#;
    let result: Result<Config, _> = toml::from_str(toml_str);
    assert!(result.is_err(), "target without name should fail to parse");
}

// ─────────────────────────────────────────────────────────────────────────────
// Context file
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn target_context_file_is_optional() {
    let toml_str = r#"
[[targets]]
name = "no-context"
type = "local"
"#;
    let config: Config = toml::from_str(toml_str).expect("should parse without context_file");
    let targets = config.targets.expect("targets should be present");
    assert!(targets[0].context_file.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// No targets is valid (user hasn't configured anything yet)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn config_without_targets_is_valid() {
    let toml_str = r#"
default_temperature = 0.7
"#;
    let config: Config = toml::from_str(toml_str).expect("config without targets should parse");
    assert!(
        config.targets.is_none(),
        "missing targets section should be None"
    );
}
