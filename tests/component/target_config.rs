use zeroclaw::config::schema::{validate_targets, OpsClawAutonomy, TargetConfig, TargetType};

fn ssh_target(name: &str) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        target_type: TargetType::Ssh,
        host: Some("203.0.113.10".to_string()),
        port: Some(22),
        user: Some("opsclaw".to_string()),
        key_secret: Some(format!("{name}-key")),
        autonomy: OpsClawAutonomy::Observe,
        context_file: None,
    }
}

fn local_target(name: &str) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        target_type: TargetType::Local,
        host: None,
        port: None,
        user: None,
        key_secret: None,
        autonomy: OpsClawAutonomy::Observe,
        context_file: Some(format!("context/{name}.md")),
    }
}

#[test]
fn parse_valid_ssh_target_from_toml() {
    let toml_str = r#"
[[targets]]
name = "prod-web-1"
type = "ssh"
host = "203.0.113.10"
port = 22
user = "opsclaw"
key_secret = "prod-web-1-key"
autonomy = "observe"
context_file = "context/prod-web-1.md"
"#;

    #[derive(serde::Deserialize)]
    struct Wrapper {
        targets: Vec<TargetConfig>,
    }

    let w: Wrapper = toml::from_str(toml_str).expect("valid TOML");
    assert_eq!(w.targets.len(), 1);
    let t = &w.targets[0];
    assert_eq!(t.name, "prod-web-1");
    assert_eq!(t.target_type, TargetType::Ssh);
    assert_eq!(t.host.as_deref(), Some("203.0.113.10"));
    assert_eq!(t.port, Some(22));
    assert_eq!(t.user.as_deref(), Some("opsclaw"));
    assert_eq!(t.key_secret.as_deref(), Some("prod-web-1-key"));
    assert_eq!(t.autonomy, OpsClawAutonomy::Observe);
}

#[test]
fn parse_valid_local_target_from_toml() {
    let toml_str = r#"
[[targets]]
name = "this-box"
type = "local"
autonomy = "observe"
context_file = "context/this-box.md"
"#;

    #[derive(serde::Deserialize)]
    struct Wrapper {
        targets: Vec<TargetConfig>,
    }

    let w: Wrapper = toml::from_str(toml_str).expect("valid TOML");
    assert_eq!(w.targets.len(), 1);
    let t = &w.targets[0];
    assert_eq!(t.name, "this-box");
    assert_eq!(t.target_type, TargetType::Local);
    assert!(t.host.is_none());
    assert!(t.user.is_none());
    assert!(t.key_secret.is_none());
}

#[test]
fn parse_multiple_targets() {
    let toml_str = r#"
[[targets]]
name = "prod-web-1"
type = "ssh"
host = "203.0.113.10"
port = 22
user = "opsclaw"
key_secret = "prod-web-1-key"
autonomy = "act_on_known"

[[targets]]
name = "this-box"
type = "local"
autonomy = "suggest"
"#;

    #[derive(serde::Deserialize)]
    struct Wrapper {
        targets: Vec<TargetConfig>,
    }

    let w: Wrapper = toml::from_str(toml_str).expect("valid TOML");
    assert_eq!(w.targets.len(), 2);
    assert_eq!(w.targets[0].autonomy, OpsClawAutonomy::ActOnKnown);
    assert_eq!(w.targets[1].autonomy, OpsClawAutonomy::Suggest);
    validate_targets(&w.targets).expect("validation should pass");
}

#[test]
fn all_autonomy_levels_parse() {
    for (input, expected) in [
        ("observe", OpsClawAutonomy::Observe),
        ("suggest", OpsClawAutonomy::Suggest),
        ("act_on_known", OpsClawAutonomy::ActOnKnown),
        ("full_auto", OpsClawAutonomy::FullAuto),
    ] {
        let toml_str = format!(
            r#"
[[targets]]
name = "t"
type = "local"
autonomy = "{input}"
"#
        );

        #[derive(serde::Deserialize)]
        struct Wrapper {
            targets: Vec<TargetConfig>,
        }

        let w: Wrapper = toml::from_str(&toml_str).unwrap_or_else(|e| {
            panic!("Failed to parse autonomy level '{input}': {e}");
        });
        assert_eq!(w.targets[0].autonomy, expected);
    }
}

#[test]
fn validate_rejects_duplicate_names() {
    let targets = vec![ssh_target("dup"), ssh_target("dup")];
    let err = validate_targets(&targets).unwrap_err();
    assert!(
        err.to_string().contains("Duplicate target name"),
        "Expected duplicate name error, got: {err}"
    );
}

#[test]
fn validate_rejects_ssh_missing_host() {
    let targets = vec![TargetConfig {
        host: None,
        ..ssh_target("bad-ssh")
    }];
    let err = validate_targets(&targets).unwrap_err();
    assert!(err.to_string().contains("missing required field 'host'"));
}

#[test]
fn validate_rejects_ssh_missing_user() {
    let targets = vec![TargetConfig {
        user: None,
        ..ssh_target("bad-ssh")
    }];
    let err = validate_targets(&targets).unwrap_err();
    assert!(err.to_string().contains("missing required field 'user'"));
}

#[test]
fn validate_rejects_ssh_missing_key_secret() {
    let targets = vec![TargetConfig {
        key_secret: None,
        ..ssh_target("bad-ssh")
    }];
    let err = validate_targets(&targets).unwrap_err();
    assert!(err
        .to_string()
        .contains("missing required field 'key_secret'"));
}

#[test]
fn validate_rejects_local_with_host() {
    let targets = vec![TargetConfig {
        host: Some("should-not-be-here".to_string()),
        ..local_target("bad-local")
    }];
    let err = validate_targets(&targets).unwrap_err();
    assert!(err.to_string().contains("must not have 'host'"));
}

#[test]
fn validate_rejects_local_with_user() {
    let targets = vec![TargetConfig {
        user: Some("should-not-be-here".to_string()),
        ..local_target("bad-local")
    }];
    let err = validate_targets(&targets).unwrap_err();
    assert!(err.to_string().contains("must not have 'user'"));
}

#[test]
fn validate_rejects_local_with_key_secret() {
    let targets = vec![TargetConfig {
        key_secret: Some("should-not-be-here".to_string()),
        ..local_target("bad-local")
    }];
    let err = validate_targets(&targets).unwrap_err();
    assert!(err.to_string().contains("must not have 'key_secret'"));
}

#[test]
fn validate_accepts_valid_mixed_targets() {
    let targets = vec![ssh_target("prod-web-1"), local_target("this-box")];
    validate_targets(&targets).expect("mixed valid targets should pass");
}

#[test]
fn validate_empty_list_passes() {
    validate_targets(&[]).expect("empty target list should pass");
}

#[test]
fn default_autonomy_is_observe() {
    assert_eq!(OpsClawAutonomy::default(), OpsClawAutonomy::Observe);
}

#[test]
fn target_config_roundtrip_serialization() {
    let target = ssh_target("roundtrip-test");
    let json = serde_json::to_string(&target).expect("serialize");
    let deserialized: TargetConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.name, target.name);
    assert_eq!(deserialized.target_type, target.target_type);
    assert_eq!(deserialized.host, target.host);
}
