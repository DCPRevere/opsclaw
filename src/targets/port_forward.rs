//! Supervised `kubectl port-forward`s declared on kubernetes targets
//! (`[[project.env.target.port_forward]]`).
//!
//! In-cluster monitoring (Elasticsearch, Prometheus) is usually ClusterIP
//! only. Each declared forward runs `kubectl port-forward` with the target's
//! own kubeconfig, so it reaches the cluster exactly the way the
//! `kubernetes` tool does (including any `proxy-url` in that kubeconfig, such
//! as a jumpbox tunnel). It binds to 127.0.0.1 only, restarts when it drops
//! (a backing pod restarting ends a forward), and is killed when OpsClaw
//! stops. Resources then point at `http(s)://127.0.0.1:<local_port>`.

use std::path::PathBuf;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::Result;
use crate::config::{Config, SecretStore, TargetKindName};

/// How long [`start`] waits for each forward's local port to accept a
/// connection before carrying on (a slow one is warned about, not fatal).
const READY_WAIT: Duration = Duration::from_secs(15);
/// Pause before restarting a forward that exited.
const RESTART_DELAY: Duration = Duration::from_secs(3);

/// The running forwards. Dropping it stops them all.
pub struct PortForwards {
    cancel: CancellationToken,
    labels: Vec<String>,
}

impl PortForwards {
    /// No forwards (fakes mode, or none declared).
    pub fn none() -> Self {
        Self { cancel: CancellationToken::new(), labels: Vec::new() }
    }

    /// `namespace/service -> 127.0.0.1:port` for each forward, for logs and
    /// `doctor`.
    pub fn labels(&self) -> &[String] {
        &self.labels
    }
}

impl Drop for PortForwards {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[derive(Debug, Clone)]
struct Forward {
    label: String,
    kubeconfig: PathBuf,
    context: String,
    namespace: String,
    service: String,
    port: u16,
    local_port: u16,
}

/// Start every forward the config declares and wait (briefly) until each
/// local port answers.
pub async fn start(config: &Config, store: &SecretStore) -> Result<PortForwards> {
    let forwards = declared(config, store)?;
    if forwards.is_empty() {
        return Ok(PortForwards::none());
    }
    let cancel = CancellationToken::new();
    let labels = forwards.iter().map(|f| f.label.clone()).collect();
    for forward in &forwards {
        tokio::spawn(supervise(forward.clone(), cancel.child_token()));
    }
    for forward in &forwards {
        if wait_ready(forward.local_port).await {
            tracing::info!(forward = %forward.label, "port-forward ready");
        } else {
            tracing::warn!(
                forward = %forward.label,
                "port-forward not answering yet; its resource will fail until it does"
            );
        }
    }
    Ok(PortForwards { cancel, labels })
}

fn declared(config: &Config, store: &SecretStore) -> Result<Vec<Forward>> {
    let mut out = Vec::new();
    for project in &config.projects {
        for env in &project.envs {
            for target in &env.targets {
                if target.port_forwards.is_empty() || target.kind != TargetKindName::Kubernetes {
                    continue;
                }
                let fq = format!("{}::{}::{}", project.name, env.name, target.name);
                let kubeconfig = match &target.credential {
                    Some(r) => PathBuf::from(r.resolve(store)?),
                    None => {
                        return Err(crate::Error::Config(format!(
                            "{fq}: port_forward needs the target's kubeconfig credential"
                        )));
                    }
                };
                let context =
                    target.kubernetes.as_ref().map(|k| k.context.clone()).ok_or_else(|| {
                        crate::Error::Config(format!(
                            "{fq}: port_forward needs the target's kubernetes block"
                        ))
                    })?;
                for pf in &target.port_forwards {
                    out.push(Forward {
                        label: format!(
                            "{fq}: {}/{}:{} -> 127.0.0.1:{}",
                            pf.namespace, pf.service, pf.port, pf.local_port
                        ),
                        kubeconfig: kubeconfig.clone(),
                        context: context.clone(),
                        namespace: pf.namespace.clone(),
                        service: pf.service.clone(),
                        port: pf.port,
                        local_port: pf.local_port,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// The kubectl arguments for one forward.
fn kubectl_args(f: &Forward) -> Vec<String> {
    vec![
        "--kubeconfig".into(),
        f.kubeconfig.display().to_string(),
        "--context".into(),
        f.context.clone(),
        "-n".into(),
        f.namespace.clone(),
        "port-forward".into(),
        "--address".into(),
        "127.0.0.1".into(),
        format!("svc/{}", f.service),
        format!("{}:{}", f.local_port, f.port),
    ]
}

async fn supervise(forward: Forward, cancel: CancellationToken) {
    loop {
        let spawned = tokio::process::Command::new("kubectl")
            .args(kubectl_args(&forward))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        match spawned {
            Ok(mut child) => {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        let _ = child.kill().await;
                        return;
                    }
                    status = child.wait() => {
                        tracing::warn!(
                            forward = %forward.label,
                            ?status,
                            "port-forward exited; restarting"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(forward = %forward.label, "could not start kubectl port-forward: {e}")
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(RESTART_DELAY) => {}
        }
    }
}

async fn wait_ready(port: u16) -> bool {
    let deadline = tokio::time::Instant::now() + READY_WAIT;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forward_uses_the_targets_kubeconfig_and_binds_to_loopback() {
        let f = Forward {
            label: "x".into(),
            kubeconfig: PathBuf::from("/k/sandbox.yaml"),
            context: "opsclaw-sandbox".into(),
            namespace: "monitoring".into(),
            service: "prometheus".into(),
            port: 9090,
            local_port: 9202,
        };
        assert_eq!(
            kubectl_args(&f).join(" "),
            "--kubeconfig /k/sandbox.yaml --context opsclaw-sandbox -n monitoring port-forward \
             --address 127.0.0.1 svc/prometheus 9202:9090"
        );
    }

    #[test]
    fn declared_forwards_come_from_kubernetes_targets() {
        let config: Config = toml::from_str(
            r#"
            [[project]]
            name = "p"
            [[project.env]]
            name = "e"
            [[project.env.target]]
            name = "aks"
            kind = "kubernetes"
            credential = "env:OPSCLAW_PF_TEST_KUBECONFIG"
            [project.env.target.kubernetes]
            context = "ctx"
            cluster_scoped = true
            [[project.env.target.port_forward]]
            namespace = "monitoring"
            service = "prometheus"
            port = 9090
            local_port = 9202
            "#,
        )
        .unwrap();
        unsafe { std::env::set_var("OPSCLAW_PF_TEST_KUBECONFIG", "/k/sandbox.yaml") };
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(dir.path()).unwrap();
        let forwards = declared(&config, &store).unwrap();
        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].context, "ctx");
        assert_eq!(forwards[0].kubeconfig, PathBuf::from("/k/sandbox.yaml"));
        assert!(forwards[0].label.contains("monitoring/prometheus:9090 -> 127.0.0.1:9202"));
    }
}
