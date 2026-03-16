use zeroclaw::tools::discovery::CommandRunner;
use zeroclaw::tools::ssh_command_runner::{LocalCommandRunner, SshCommandRunner};
use zeroclaw::tools::ssh_tool::{OpsClawAutonomy, SshExecutor, SshOutput, TargetEntry};

use std::time::Duration;

// ── Mock executor ───────────────────────────────────────

struct MockExecutor {
    output: SshOutput,
    delay: Option<Duration>,
}

impl MockExecutor {
    fn ok(stdout: &str) -> Self {
        Self {
            output: SshOutput {
                stdout: stdout.into(),
                stderr: String::new(),
                exit_code: 0,
            },
            delay: None,
        }
    }

    fn with_delay(mut self, d: Duration) -> Self {
        self.delay = Some(d);
        self
    }
}

#[async_trait::async_trait]
impl SshExecutor for MockExecutor {
    async fn run(
        &self,
        _target: &TargetEntry,
        _command: &str,
        _timeout: Duration,
        _pty: bool,
    ) -> anyhow::Result<SshOutput> {
        if let Some(d) = self.delay {
            tokio::time::sleep(d).await;
        }
        Ok(self.output.clone())
    }
}

// ── Helpers ─────────────────────────────────────────────

fn target(autonomy: OpsClawAutonomy) -> TargetEntry {
    TargetEntry {
        name: "test-host".into(),
        host: "127.0.0.1".into(),
        port: 22,
        user: "root".into(),
        private_key_pem: "fake".into(),
        autonomy,
    }
}

// ── LocalCommandRunner: observe mode ────────────────────

#[tokio::test]
async fn local_observe_rejects_write_commands() {
    let runner = LocalCommandRunner::new(OpsClawAutonomy::Observe, "local".into());

    let err = runner.run("rm -rf /tmp/data").await.unwrap_err();
    assert!(
        err.to_string().contains("observe mode"),
        "expected observe mode rejection, got: {err}"
    );

    let err = runner.run("mv a b").await.unwrap_err();
    assert!(err.to_string().contains("observe mode"));

    let err = runner.run("docker restart nginx").await.unwrap_err();
    assert!(err.to_string().contains("observe mode"));
}

// ── LocalCommandRunner: echo capture ────────────────────

#[tokio::test]
async fn local_captures_echo_output() {
    let tmp = tempfile::tempdir().unwrap();
    let runner = LocalCommandRunner::new(OpsClawAutonomy::FullAuto, "local".into())
        .with_audit_dir(tmp.path().to_path_buf());

    let out = runner.run("echo hello").await.unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.stdout.trim(), "hello");
    assert!(out.stderr.is_empty());
}

// ── LocalCommandRunner: audit log ───────────────────────

#[tokio::test]
async fn local_writes_audit_log() {
    let tmp = tempfile::tempdir().unwrap();
    let runner = LocalCommandRunner::new(OpsClawAutonomy::FullAuto, "sidecar".into())
        .with_audit_dir(tmp.path().to_path_buf());

    runner.run("echo audit-test").await.unwrap();

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let log_path = tmp.path().join(format!("{date}.log"));
    assert!(log_path.exists(), "audit log should exist");

    let log = std::fs::read_to_string(log_path).unwrap();
    assert!(log.contains("TARGET=sidecar"), "missing target");
    assert!(log.contains("CMD=echo audit-test"), "missing command");
    assert!(log.contains("EXIT=0"), "missing exit code");
}

// ── LocalCommandRunner: timeout ─────────────────────────

#[tokio::test]
async fn local_timeout_is_enforced() {
    let runner =
        LocalCommandRunner::new(OpsClawAutonomy::FullAuto, "local".into()).with_timeout_secs(1);

    let err = runner.run("sleep 30").await.unwrap_err();
    assert!(
        err.to_string().contains("timed out"),
        "expected timeout error, got: {err}"
    );
}

// ── SshCommandRunner: observe mode via mock ─────────────

#[tokio::test]
async fn ssh_observe_rejects_write() {
    let runner = SshCommandRunner::new(
        target(OpsClawAutonomy::Observe),
        Box::new(MockExecutor::ok("")),
    );

    let err = runner.run("rm -rf /tmp").await.unwrap_err();
    assert!(err.to_string().contains("observe mode"));
}

#[tokio::test]
async fn ssh_observe_allows_read() {
    let tmp = tempfile::tempdir().unwrap();
    let runner = SshCommandRunner::new(
        target(OpsClawAutonomy::Observe),
        Box::new(MockExecutor::ok("Linux 6.1")),
    )
    .with_audit_dir(tmp.path().to_path_buf());

    let out = runner.run("uname -a").await.unwrap();
    assert_eq!(out.stdout, "Linux 6.1");
    assert_eq!(out.exit_code, 0);
}

// ── SshCommandRunner: timeout via mock ──────────────────

#[tokio::test]
async fn ssh_timeout_is_enforced() {
    let runner = SshCommandRunner::new(
        target(OpsClawAutonomy::FullAuto),
        Box::new(MockExecutor::ok("").with_delay(Duration::from_secs(5))),
    )
    .with_timeout(Duration::from_millis(50));

    let err = runner.run("sleep 999").await.unwrap_err();
    assert!(err.to_string().contains("timed out"));
}

// ── SshCommandRunner: audit log via mock ────────────────

#[tokio::test]
async fn ssh_writes_audit_log() {
    let tmp = tempfile::tempdir().unwrap();
    let runner = SshCommandRunner::new(
        target(OpsClawAutonomy::FullAuto),
        Box::new(MockExecutor::ok("ok")),
    )
    .with_audit_dir(tmp.path().to_path_buf());

    runner.run("uptime").await.unwrap();

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let log = std::fs::read_to_string(tmp.path().join(format!("{date}.log"))).unwrap();
    assert!(log.contains("CMD=uptime"));
    assert!(log.contains("TARGET=test-host"));
}
