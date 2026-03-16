use std::io::Write;
use tempfile::TempDir;
use zeroclaw::config::schema::{OpsClawAutonomy, TargetConfig, TargetType};
use zeroclaw::config::Config;
use zeroclaw::ops::OpsClawContext;
use zeroclaw::OpsClawSecretStore;

fn test_config(targets: Vec<TargetConfig>) -> Config {
    Config {
        targets: Some(targets),
        ..Config::default()
    }
}

fn sacra_target() -> TargetConfig {
    TargetConfig {
        name: "sacra".to_string(),
        target_type: TargetType::Ssh,
        host: Some("159.69.92.65".to_string()),
        port: Some(22),
        user: Some("root".to_string()),
        key_secret: Some("sacra-hetzner-key".to_string()),
        autonomy: OpsClawAutonomy::Observe,
        context_file: None,
    }
}

#[test]
fn context_returns_configured_targets() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    let config = test_config(vec![sacra_target()]);
    let ctx = OpsClawContext::new(config, secrets);

    let targets = ctx.targets();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].name, "sacra");
}

#[test]
fn context_returns_empty_targets_when_none() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    let config = Config {
        targets: None,
        ..Config::default()
    };
    let ctx = OpsClawContext::new(config, secrets);

    assert!(ctx.targets().is_empty());
}

#[test]
fn ssh_runner_for_returns_correct_host_port_user() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    secrets
        .set(
            "sacra-hetzner-key",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
        )
        .unwrap();

    let config = test_config(vec![sacra_target()]);
    let ctx = OpsClawContext::new(config, secrets);

    let runner = ctx.ssh_runner_for("sacra").unwrap();
    assert_eq!(runner.host(), "159.69.92.65");
    assert_eq!(runner.port(), 22);
    assert_eq!(runner.user(), "root");
}

#[test]
fn ssh_runner_for_resolves_key_from_secret_store() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    let key_content =
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-key-data\n-----END OPENSSH PRIVATE KEY-----";
    secrets.set("sacra-hetzner-key", key_content).unwrap();

    let config = test_config(vec![sacra_target()]);
    let ctx = OpsClawContext::new(config, secrets);

    let runner = ctx.ssh_runner_for("sacra").unwrap();
    assert_eq!(runner.target().private_key_pem, key_content);
}

#[test]
fn ssh_runner_for_unknown_target_errors() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    let config = test_config(vec![sacra_target()]);
    let ctx = OpsClawContext::new(config, secrets);

    let err = ctx.ssh_runner_for("nonexistent").unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[test]
fn ssh_runner_for_missing_secret_errors() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    // Don't set the secret — it should fail.
    let config = test_config(vec![sacra_target()]);
    let ctx = OpsClawContext::new(config, secrets);

    let err = ctx.ssh_runner_for("sacra").unwrap_err();
    assert!(err.to_string().contains("not found in secret store"));
}

#[test]
fn ssh_runner_for_local_target_errors() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    let config = test_config(vec![TargetConfig {
        name: "local-box".to_string(),
        target_type: TargetType::Local,
        host: None,
        port: None,
        user: None,
        key_secret: None,
        autonomy: OpsClawAutonomy::Observe,
        context_file: None,
    }]);
    let ctx = OpsClawContext::new(config, secrets);

    let err = ctx.ssh_runner_for("local-box").unwrap_err();
    assert!(err.to_string().contains("not an SSH target"));
}

#[test]
fn ssh_runner_uses_default_port_22() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    secrets.set("sacra-hetzner-key", "fake-key").unwrap();

    let mut target = sacra_target();
    target.port = None; // no explicit port
    let config = test_config(vec![target]);
    let ctx = OpsClawContext::new(config, secrets);

    let runner = ctx.ssh_runner_for("sacra").unwrap();
    assert_eq!(runner.port(), 22);
}

#[test]
fn context_for_reads_context_file() {
    let tmp = TempDir::new().unwrap();
    let context_path = tmp.path().join("sacra-context.md");
    let context_content = "# Sacra\nF# web app on Hetzner.\n";
    {
        let mut f = std::fs::File::create(&context_path).unwrap();
        f.write_all(context_content.as_bytes()).unwrap();
    }

    let secrets = OpsClawSecretStore::new(tmp.path());
    let mut target = sacra_target();
    target.context_file = Some(context_path.to_string_lossy().to_string());
    let config = test_config(vec![target]);
    let ctx = OpsClawContext::new(config, secrets);

    let content = ctx.context_for("sacra").unwrap();
    assert_eq!(content, context_content);
}

#[test]
fn context_for_missing_file_errors() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    let mut target = sacra_target();
    target.context_file = Some("/nonexistent/path.md".to_string());
    let config = test_config(vec![target]);
    let ctx = OpsClawContext::new(config, secrets);

    let err = ctx.context_for("sacra").unwrap_err();
    assert!(err.to_string().contains("failed to read context file"));
}

#[test]
fn context_for_no_context_file_configured_errors() {
    let tmp = TempDir::new().unwrap();
    let secrets = OpsClawSecretStore::new(tmp.path());
    let config = test_config(vec![sacra_target()]); // sacra_target has context_file = None
    let ctx = OpsClawContext::new(config, secrets);

    let err = ctx.context_for("sacra").unwrap_err();
    assert!(err.to_string().contains("no context_file configured"));
}
