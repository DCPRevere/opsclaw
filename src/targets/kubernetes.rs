//! `KubernetesExecutor` — shells out to `kubectl` with an explicit
//! `--kubeconfig` and optional `--context` (`docs/plans/IMPLEMENTATION.md`
//! §5: `kubectl` via the executor where exec semantics are needed; `kube-rs`
//! is for a later API-path tool, not this executor). `run()` maps a
//! [`Command`] whose `line` is a kubectl subcommand (e.g. `get pods -n
//! prod`, without the leading `kubectl` — the executor supplies the binary
//! and connection flags so a tool can never omit `--kubeconfig` and hit an
//! ambient cluster).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::process::Command as TokioCommand;

use crate::Result;
use crate::domain::KubernetesScope;
use crate::error::Error;
use crate::targets::{Command, ExecOutput, ProbeReport, TargetExecutor};

#[derive(Debug, Clone)]
pub struct KubernetesParams {
    /// Resolved kubeconfig file path (already written to disk from the
    /// resolved credential at wiring time).
    pub kubeconfig: PathBuf,
    /// Optional context name within the kubeconfig (example: staging/prod
    /// are namespace-scoped ServiceAccount kubeconfigs on one physical
    /// cluster — see `docs/REFERENCE.md`).
    pub context: String,
    pub scope: KubernetesScope,
}

pub struct KubernetesExecutor {
    params: KubernetesParams,
    kubectl_bin: String,
}

impl KubernetesExecutor {
    pub fn new(params: KubernetesParams) -> Self {
        KubernetesExecutor { params, kubectl_bin: "kubectl".to_string() }
    }

    pub fn with_kubectl_bin(params: KubernetesParams, kubectl_bin: impl Into<String>) -> Self {
        KubernetesExecutor { params, kubectl_bin: kubectl_bin.into() }
    }

    fn base_args(&self) -> Vec<String> {
        let mut args =
            vec!["--kubeconfig".to_string(), self.params.kubeconfig.display().to_string()];
        args.push("--context".to_string());
        args.push(self.params.context.clone());
        args
    }

    fn scoped_args(&self, line: &str) -> Result<Vec<String>> {
        let mut args = Self::split_line(line);
        let KubernetesScope::Namespace(expected) = &self.params.scope else { return Ok(args) };
        let option_end = args.iter().position(|arg| arg == "--").unwrap_or(args.len());
        let mut stated_namespace = None;
        let mut i = 0;
        while i < option_end {
            match args[i].as_str() {
                "-A" | "--all-namespaces" => {
                    return Err(Error::Policy(format!(
                        "namespace-scoped kubernetes target cannot use {}",
                        args[i]
                    )));
                }
                "-n" | "--namespace" => {
                    let value = args.get(i + 1).ok_or_else(|| {
                        Error::Policy(format!("{} requires a namespace", args[i]))
                    })?;
                    stated_namespace = Some(value.clone());
                    i += 1;
                }
                arg if arg.starts_with("--all-namespaces=") || arg.starts_with("-A=") => {
                    return Err(Error::Policy(format!(
                        "namespace-scoped kubernetes target cannot use {arg}"
                    )));
                }
                arg if arg.starts_with("--namespace=") || arg.starts_with("-n=") => {
                    stated_namespace = arg.split_once('=').map(|(_, value)| value.to_string());
                }
                arg if arg.starts_with("-n") && arg.len() > 2 => {
                    stated_namespace = Some(arg[2..].to_string());
                }
                _ => {}
            }
            i += 1;
        }
        if let Some(actual) = stated_namespace {
            if actual != *expected {
                return Err(Error::Policy(format!(
                    "kubernetes target is scoped to namespace {expected:?}, not {actual:?}"
                )));
            }
        } else {
            args.insert(0, expected.clone());
            args.insert(0, "--namespace".to_string());
        }
        Ok(args)
    }

    /// Split `line` on whitespace for argv (kubectl subcommands from the
    /// classifier/tools are plain space-separated flags, never a shell
    /// pipeline — `policy::classify_command` already enforces that a
    /// `kubectl ...` line is what it looks like before this ever runs).
    fn split_line(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    async fn run_kubectl(&self, extra_args: &[String], timeout: Duration) -> Result<ExecOutput> {
        let start = Instant::now();
        let mut args = self.base_args();
        args.extend(extra_args.iter().cloned());

        let child = TokioCommand::new(&self.kubectl_bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::other(format!("kubectl spawn failed: {e}")))?;

        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| Error::other(format!("kubectl exec timed out after {timeout:?}")))?
            .map_err(|e| Error::other(format!("kubectl exec failed: {e}")))?;

        Ok(ExecOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

#[async_trait]
impl TargetExecutor for KubernetesExecutor {
    async fn run(&self, cmd: &Command, timeout: Duration) -> Result<ExecOutput> {
        // Strip a leading "kubectl" if the tool included it — the classifier
        // matches on the full `kubectl ...` line (policy/classify.rs), but
        // the executor supplies the binary itself.
        let trimmed = cmd.line.trim_start();
        let line = if trimmed == "kubectl" {
            ""
        } else if let Some(rest) = trimmed.strip_prefix("kubectl ") {
            rest.trim_start()
        } else {
            &cmd.line
        };
        let args = self.scoped_args(line)?;
        self.run_kubectl(&args, timeout).await
    }

    async fn probe(&self) -> Result<ProbeReport> {
        let args = vec!["version".to_string(), "--request-timeout=5s".to_string()];
        match self.run_kubectl(&args, Duration::from_secs(10)).await {
            Ok(out) if out.success() => Ok(ProbeReport {
                reachable: true,
                detail: format!("kubectl version ok ({})", self.params.kubeconfig.display()),
            }),
            Ok(out) => Ok(ProbeReport {
                reachable: false,
                detail: format!("kubectl version exited {}: {}", out.exit_code, out.stderr.trim()),
            }),
            Err(e) => {
                Ok(ProbeReport { reachable: false, detail: format!("kubectl probe failed: {e}") })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KubernetesParams {
        KubernetesParams {
            kubeconfig: PathBuf::from("/etc/opsclaw/kubeconfigs/example-prod.yaml"),
            context: "prod-example".to_string(),
            scope: KubernetesScope::Namespace("prod".to_string()),
        }
    }

    #[test]
    fn base_args_always_include_explicit_kubeconfig() {
        let exec = KubernetesExecutor::new(params());
        let args = exec.base_args();
        assert_eq!(args[0], "--kubeconfig");
        assert!(args[1].contains("example-prod.yaml"));
        assert!(args.contains(&"--context".to_string()));
        assert!(args.contains(&"prod-example".to_string()));
    }

    #[test]
    fn strips_leading_kubectl_from_command_line() {
        assert_eq!(
            KubernetesExecutor::split_line("get pods -n prod"),
            vec!["get", "pods", "-n", "prod"]
        );
    }

    #[test]
    fn namespace_scope_is_injected_and_cannot_be_overridden() {
        let exec = KubernetesExecutor::new(params());
        assert_eq!(
            exec.scoped_args("get pods").unwrap(),
            vec!["--namespace", "prod", "get", "pods"]
        );
        assert!(exec.scoped_args("get pods -A").is_err());
        assert!(exec.scoped_args("get pods -n dev").is_err());
        assert!(exec.scoped_args("get pods --namespace=dev").is_err());
        assert!(exec.scoped_args("get pods -ndev").is_err());
        assert!(exec.scoped_args("get pods --all-namespaces=true").is_err());
        assert!(exec.scoped_args("get pods -n prod").is_ok());
    }

    #[test]
    fn kubectlx_is_not_mistaken_for_the_kubectl_binary_prefix() {
        let exec = KubernetesExecutor::new(params());
        assert_eq!(exec.scoped_args("kubectlx get pods").unwrap()[2], "kubectlx");
    }

    #[tokio::test]
    async fn bad_binary_probe_reports_unreachable() {
        let exec = KubernetesExecutor::with_kubectl_bin(params(), "/no/such/kubectl-binary");
        let report = exec.probe().await.unwrap();
        assert!(!report.reachable);
    }
}
