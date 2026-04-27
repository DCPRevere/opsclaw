//! Kubernetes API client for discovery, log retrieval, remediation, and event
//! watching.
//!
//! Wraps [`kube::Client`] and translates API responses into the
//! [`KubernetesInfo`] snapshot structs defined in [`super::discovery`].

use anyhow::{Context, Result};
use chrono::Utc;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Event, Namespace, Node, Pod, Service};
use kube::api::{Api, ListParams, LogParams, Patch, PatchParams};
use kube::config::KubeConfigOptions;
use kube::Client;
use serde::Serialize;
use tracing::{debug, error};

use super::discovery::{
    K8sDeployment, K8sNode, K8sPod, K8sService, KubernetesInfo, TargetSnapshot,
};

/// Thin wrapper around [`kube::Client`] that provides typed helpers for
/// the operations OpsClaw needs.
pub struct KubeClient {
    client: Client,
}

/// A single Kubernetes event for the watch command.
#[derive(Debug, Clone, Serialize)]
pub struct K8sEvent {
    pub reason: String,
    pub message: String,
    pub involved_object: String,
    pub timestamp: String,
}

/// Abstraction over how a [`KubeClient`] is constructed so that tests can
/// substitute a fake.
#[async_trait::async_trait]
pub trait KubeClientFactory: Send + Sync {
    async fn build(&self, kubeconfig: Option<&str>, context: Option<&str>) -> Result<KubeClient>;
}

/// Default factory that creates a real client from the environment or a
/// specific kubeconfig path.
pub struct DefaultKubeClientFactory;

#[async_trait::async_trait]
impl KubeClientFactory for DefaultKubeClientFactory {
    async fn build(&self, kubeconfig: Option<&str>, context: Option<&str>) -> Result<KubeClient> {
        KubeClient::new(kubeconfig, context).await
    }
}

impl KubeClient {
    /// Create a new client.
    ///
    /// If `kubeconfig` is `Some`, that path is used; otherwise the default
    /// kubeconfig resolution order applies (~/.kube/config, in-cluster).
    /// If `context` is `Some`, that kubeconfig context is selected; otherwise
    /// the kubeconfig's `current-context` applies.
    pub async fn new(kubeconfig: Option<&str>, context: Option<&str>) -> Result<Self> {
        let options = KubeConfigOptions {
            context: context.map(String::from),
            ..Default::default()
        };
        let config = match kubeconfig {
            Some(path) => {
                let kubeconfig = kube::config::Kubeconfig::read_from(path)
                    .context("failed to read kubeconfig")?;
                kube::Config::from_custom_kubeconfig(kubeconfig, &options)
                    .await
                    .context("failed to build kube config")?
            }
            None => kube::Config::infer()
                .await
                .context("failed to infer kube config")?,
        };
        let client = Client::try_from(config).context("failed to build kube client")?;
        Ok(Self { client })
    }

    // ------------------------------------------------------------------
    // Discovery
    // ------------------------------------------------------------------

    /// Perform a full Kubernetes discovery scan and return a
    /// [`KubernetesInfo`] snapshot.
    pub async fn discover_k8s(&self) -> Result<KubernetesInfo> {
        debug!("Starting Kubernetes discovery");
        // cluster_version is informational (may require privileges old RBAC
        // rejects); the rest of the snapshot is meaningful without it.
        let cluster_info = match self.cluster_version().await {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "Failed to retrieve cluster version — continuing without it");
                String::new()
            }
        };
        let namespaces = self.list_namespaces().await.context("list namespaces")?;
        let pods = self.list_pods(None).await.context("list pods")?;
        let deployments = self.list_deployments(None).await.context("list deployments")?;
        let services = self.list_services(None).await.context("list services")?;
        let nodes = self.list_nodes().await.context("list nodes")?;
        debug!(
            pods = pods.len(),
            deployments = deployments.len(),
            services = services.len(),
            nodes = nodes.len(),
            "Kubernetes discovery complete"
        );

        Ok(KubernetesInfo {
            cluster_info,
            namespaces,
            pods,
            deployments,
            services,
            nodes,
        })
    }

    /// Build a minimal [`TargetSnapshot`] populated only with Kubernetes data.
    pub async fn discover_snapshot(&self) -> Result<TargetSnapshot> {
        let k8s = self.discover_k8s().await?;
        Ok(TargetSnapshot {
            scanned_at: Utc::now(),
            os: super::discovery::OsInfo {
                uname: String::new(),
                distro_name: String::from("kubernetes"),
                distro_version: k8s.cluster_info.clone(),
            },
            containers: Vec::new(),
            services: Vec::new(),
            listening_ports: Vec::new(),
            disk: Vec::new(),
            memory: super::discovery::MemoryInfo {
                total_mb: 0,
                used_mb: 0,
                free_mb: 0,
                available_mb: 0,
            },
            load: super::discovery::LoadInfo {
                load_1: 0.0,
                load_5: 0.0,
                load_15: 0.0,
                uptime: String::new(),
            },
            kubernetes: Some(k8s),
        })
    }

    // ------------------------------------------------------------------
    // Logs
    // ------------------------------------------------------------------

    /// Retrieve the last `lines` of log output from a pod.
    pub async fn get_pod_logs(&self, namespace: &str, pod: &str, lines: i64) -> Result<String> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let lp = LogParams {
            tail_lines: Some(lines),
            ..Default::default()
        };
        pods.logs(pod, &lp)
            .await
            .with_context(|| format!("failed to get logs for {namespace}/{pod}"))
    }

    // ------------------------------------------------------------------
    // Remediation
    // ------------------------------------------------------------------

    /// Restart a deployment by annotating its pod template (the standard
    /// `kubectl rollout restart` approach).
    pub async fn restart_deployment(&self, namespace: &str, name: &str) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        let restart_annotation = serde_json::json!({
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": Utc::now().to_rfc3339()
                        }
                    }
                }
            }
        });
        deployments
            .patch(
                name,
                &PatchParams::apply("opsclaw"),
                &Patch::Strategic(restart_annotation),
            )
            .await
            .with_context(|| format!("failed to restart deployment {namespace}/{name}"))?;
        Ok(())
    }

    /// Scale a deployment to `replicas` by patching its `spec.replicas`.
    pub async fn scale_deployment(
        &self,
        namespace: &str,
        name: &str,
        replicas: i32,
    ) -> Result<()> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        let patch = serde_json::json!({ "spec": { "replicas": replicas } });
        deployments
            .patch(name, &PatchParams::default(), &Patch::Merge(patch))
            .await
            .with_context(|| format!("failed to scale {namespace}/{name} to {replicas}"))?;
        Ok(())
    }

    /// Delete a pod (the controller will recreate if it's managed).
    pub async fn delete_pod(&self, namespace: &str, name: &str) -> Result<()> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        pods.delete(name, &kube::api::DeleteParams::default())
            .await
            .with_context(|| format!("failed to delete pod {namespace}/{name}"))?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Events (for watch command)
    // ------------------------------------------------------------------

    /// Return recent events for a namespace (or all namespaces if `namespace`
    /// is `None`).
    pub async fn get_events(&self, namespace: Option<&str>) -> Result<Vec<K8sEvent>> {
        let events: Api<Event> = match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let list = events
            .list(&ListParams::default())
            .await
            .context("failed to list events")?;

        Ok(list
            .items
            .into_iter()
            .map(|e| {
                let obj = e.involved_object;
                let obj_str = format!(
                    "{}/{}",
                    obj.kind.as_deref().unwrap_or("Unknown"),
                    obj.name.as_deref().unwrap_or("unknown"),
                );
                K8sEvent {
                    reason: e.reason.unwrap_or_default(),
                    message: e.message.unwrap_or_default(),
                    involved_object: obj_str,
                    timestamp: e
                        .last_timestamp
                        .map(|t| t.0.to_rfc3339())
                        .unwrap_or_default(),
                }
            })
            .collect())
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    pub(crate) async fn cluster_version(&self) -> Result<String> {
        let version = self.client.apiserver_version().await?;
        Ok(format!("v{}.{}", version.major, version.minor))
    }

    pub(crate) async fn list_namespaces(&self) -> Result<Vec<String>> {
        let ns_api: Api<Namespace> = Api::all(self.client.clone());
        let list = ns_api.list(&ListParams::default()).await?;
        Ok(list
            .items
            .iter()
            .filter_map(|ns| ns.metadata.name.clone())
            .collect())
    }

    pub(crate) async fn list_pods(&self, namespace: Option<&str>) -> Result<Vec<K8sPod>> {
        let pods: Api<Pod> = match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let list = pods.list(&ListParams::default()).await?;
        Ok(list.items.into_iter().map(pod_to_snapshot).collect())
    }

    pub(crate) async fn list_deployments(&self, namespace: Option<&str>) -> Result<Vec<K8sDeployment>> {
        let deps: Api<Deployment> = match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let list = deps.list(&ListParams::default()).await?;
        Ok(list.items.into_iter().map(deployment_to_snapshot).collect())
    }

    pub(crate) async fn list_services(&self, namespace: Option<&str>) -> Result<Vec<K8sService>> {
        let svcs: Api<Service> = match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let list = svcs.list(&ListParams::default()).await?;
        Ok(list.items.into_iter().map(service_to_snapshot).collect())
    }

    pub(crate) async fn list_nodes(&self) -> Result<Vec<K8sNode>> {
        let nodes: Api<Node> = Api::all(self.client.clone());
        let list = nodes.list(&ListParams::default()).await?;
        Ok(list.items.into_iter().map(node_to_snapshot).collect())
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers — typed K8s structs → snapshot structs
// ---------------------------------------------------------------------------

fn pod_to_snapshot(pod: Pod) -> K8sPod {
    let meta = pod.metadata;
    let status = pod.status.unwrap_or_default();
    let phase = status
        .phase
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());

    let container_statuses = status.container_statuses.unwrap_or_default();
    let total = container_statuses.len();
    let ready_count = container_statuses.iter().filter(|c| c.ready).count();
    let restarts: u32 = container_statuses
        .iter()
        .map(|c| c.restart_count.max(0).cast_unsigned())
        .sum();

    let waiting_reason = container_statuses.iter().find_map(|c| {
        c.state
            .as_ref()
            .and_then(|s| s.waiting.as_ref().and_then(|w| w.reason.clone()))
    });

    let detailed_status = waiting_reason.unwrap_or(phase);
    let node = pod.spec.and_then(|s| s.node_name).unwrap_or_default();

    K8sPod {
        name: meta.name.unwrap_or_default(),
        namespace: meta.namespace.unwrap_or_default(),
        status: detailed_status,
        ready: format!("{ready_count}/{total}"),
        restarts,
        age: meta
            .creation_timestamp
            .map(|t| t.0.to_rfc3339())
            .unwrap_or_default(),
        node,
    }
}

fn deployment_to_snapshot(dep: Deployment) -> K8sDeployment {
    let meta = dep.metadata;
    let spec = dep.spec.unwrap_or_default();
    let status = dep.status.unwrap_or_default();
    let desired = spec.replicas.unwrap_or(0);
    let ready_replicas = status.ready_replicas.unwrap_or(0);
    let up_to_date = status.updated_replicas.unwrap_or(0).max(0).cast_unsigned();
    let available = status
        .available_replicas
        .unwrap_or(0)
        .max(0)
        .cast_unsigned();

    K8sDeployment {
        name: meta.name.unwrap_or_default(),
        namespace: meta.namespace.unwrap_or_default(),
        ready: format!("{ready_replicas}/{desired}"),
        up_to_date,
        available,
        age: meta
            .creation_timestamp
            .map(|t| t.0.to_rfc3339())
            .unwrap_or_default(),
    }
}

fn service_to_snapshot(svc: Service) -> K8sService {
    let meta = svc.metadata;
    let spec = svc.spec.unwrap_or_default();
    let svc_type = spec
        .type_
        .clone()
        .unwrap_or_else(|| "ClusterIP".to_string());
    let cluster_ip = spec.cluster_ip.clone().unwrap_or_default();

    let lb = svc.status.and_then(|s| s.load_balancer).unwrap_or_default();
    let external_ip = lb
        .ingress
        .unwrap_or_default()
        .iter()
        .filter_map(|i| i.ip.as_deref().or(i.hostname.as_deref()))
        .collect::<Vec<_>>()
        .join(",");
    let external_ip = if external_ip.is_empty() {
        "<none>".to_string()
    } else {
        external_ip
    };

    let ports = spec
        .ports
        .unwrap_or_default()
        .iter()
        .map(|p| format!("{}/{}", p.port, p.protocol.as_deref().unwrap_or("TCP")))
        .collect::<Vec<_>>()
        .join(",");

    K8sService {
        name: meta.name.unwrap_or_default(),
        namespace: meta.namespace.unwrap_or_default(),
        svc_type,
        cluster_ip,
        external_ip,
        ports,
        age: meta
            .creation_timestamp
            .map(|t| t.0.to_rfc3339())
            .unwrap_or_default(),
    }
}

fn node_to_snapshot(node: Node) -> K8sNode {
    let meta = node.metadata;
    let status = node.status.unwrap_or_default();

    let node_status = status
        .conditions
        .as_ref()
        .and_then(|conds| {
            conds.iter().find(|c| c.type_ == "Ready").map(|c| {
                if c.status == "True" {
                    "Ready"
                } else {
                    "NotReady"
                }
            })
        })
        .unwrap_or("Unknown");

    let labels = meta.labels.clone().unwrap_or_default();
    let roles: Vec<String> = labels
        .keys()
        .filter_map(|k| {
            k.strip_prefix("node-role.kubernetes.io/")
                .map(|r| r.to_string())
        })
        .collect();
    let roles = if roles.is_empty() {
        "<none>".to_string()
    } else {
        roles.join(",")
    };

    let version = status
        .node_info
        .map(|ni| ni.kubelet_version)
        .unwrap_or_default();

    K8sNode {
        name: meta.name.unwrap_or_default(),
        status: node_status.to_string(),
        roles,
        age: meta
            .creation_timestamp
            .map(|t| t.0.to_rfc3339())
            .unwrap_or_default(),
        version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_to_snapshot_running() {
        use k8s_openapi::api::core::v1::{
            ContainerState, ContainerStateRunning, ContainerStatus, PodSpec, PodStatus,
        };
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("web-abc12".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                node_name: Some("node-1".into()),
                ..Default::default()
            }),
            status: Some(PodStatus {
                phase: Some("Running".into()),
                container_statuses: Some(vec![ContainerStatus {
                    ready: true,
                    restart_count: 2,
                    state: Some(ContainerState {
                        running: Some(ContainerStateRunning { started_at: None }),
                        ..Default::default()
                    }),
                    name: "web".into(),
                    image: "nginx:latest".into(),
                    image_id: String::new(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        };

        let snap = pod_to_snapshot(pod);
        assert_eq!(snap.name, "web-abc12");
        assert_eq!(snap.namespace, "default");
        assert_eq!(snap.status, "Running");
        assert_eq!(snap.ready, "1/1");
        assert_eq!(snap.restarts, 2);
        assert_eq!(snap.node, "node-1");
    }

    #[test]
    fn pod_to_snapshot_crashloop() {
        use k8s_openapi::api::core::v1::{
            ContainerState, ContainerStateWaiting, ContainerStatus, PodStatus,
        };
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("crash-pod".into()),
                namespace: Some("prod".into()),
                ..Default::default()
            },
            spec: None,
            status: Some(PodStatus {
                phase: Some("Running".into()),
                container_statuses: Some(vec![ContainerStatus {
                    ready: false,
                    restart_count: 42,
                    state: Some(ContainerState {
                        waiting: Some(ContainerStateWaiting {
                            reason: Some("CrashLoopBackOff".into()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    name: "app".into(),
                    image: "myapp:latest".into(),
                    image_id: String::new(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        };

        let snap = pod_to_snapshot(pod);
        assert_eq!(snap.status, "CrashLoopBackOff");
        assert_eq!(snap.ready, "0/1");
        assert_eq!(snap.restarts, 42);
    }

    #[test]
    fn deployment_to_snapshot_healthy() {
        use k8s_openapi::api::apps::v1::{DeploymentSpec, DeploymentStatus};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let dep = Deployment {
            metadata: ObjectMeta {
                name: Some("web".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(3),
                ..Default::default()
            }),
            status: Some(DeploymentStatus {
                ready_replicas: Some(3),
                available_replicas: Some(3),
                updated_replicas: Some(3),
                ..Default::default()
            }),
        };

        let snap = deployment_to_snapshot(dep);
        assert_eq!(snap.name, "web");
        assert_eq!(snap.ready, "3/3");
        assert_eq!(snap.available, 3);
        assert_eq!(snap.up_to_date, 3);
    }

    #[test]
    fn node_to_snapshot_ready() {
        use k8s_openapi::api::core::v1::{NodeCondition, NodeStatus, NodeSystemInfo};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use std::collections::BTreeMap;

        let mut labels = BTreeMap::new();
        labels.insert(
            "node-role.kubernetes.io/control-plane".to_string(),
            String::new(),
        );

        let node = Node {
            metadata: ObjectMeta {
                name: Some("node-1".into()),
                labels: Some(labels),
                ..Default::default()
            },
            spec: None,
            status: Some(NodeStatus {
                conditions: Some(vec![NodeCondition {
                    type_: "Ready".into(),
                    status: "True".into(),
                    ..Default::default()
                }]),
                node_info: Some(NodeSystemInfo {
                    kubelet_version: "v1.31.0".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        let snap = node_to_snapshot(node);
        assert_eq!(snap.name, "node-1");
        assert_eq!(snap.status, "Ready");
        assert_eq!(snap.roles, "control-plane");
        assert_eq!(snap.version, "v1.31.0");
    }
}

// ---------------------------------------------------------------------------
// KubeTool — LLM-callable Tool wrapping KubeClient.
//
// Typed actions over the cluster. Writes (restart_deployment, scale,
// delete_pod) are gated by the target's autonomy level and audit-logged.
// ---------------------------------------------------------------------------

use crate::ops_config::{ConnectionType, OpsClawAutonomy, OpsConfig, TargetConfig};
use crate::tools::ssh_tool::write_audit_entry;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::path::PathBuf;
use zeroclaw::tools::traits::{Tool, ToolResult};

const KUBE_MAX_OUTPUT_BYTES: usize = 32 * 1024;

/// One configured Kubernetes target, resolved at registry build.
#[derive(Debug, Clone)]
pub struct KubeTarget {
    pub name: String,
    pub kubeconfig: Option<String>,
    pub context: Option<String>,
    pub default_namespace: Option<String>,
    pub autonomy: OpsClawAutonomy,
}

pub struct KubeToolConfig {
    pub targets: Vec<KubeTarget>,
}

pub struct KubeTool {
    config: KubeToolConfig,
    factory: Box<dyn KubeClientFactory>,
    audit_dir: Option<PathBuf>,
}

impl KubeTool {
    pub fn new(config: KubeToolConfig) -> Self {
        Self {
            config,
            factory: Box::new(DefaultKubeClientFactory),
            audit_dir: None,
        }
    }

    pub fn with_factory(config: KubeToolConfig, factory: Box<dyn KubeClientFactory>) -> Self {
        Self {
            config,
            factory,
            audit_dir: None,
        }
    }

    pub fn with_audit_dir(mut self, dir: PathBuf) -> Self {
        self.audit_dir = Some(dir);
        self
    }

    /// Build Kubernetes target entries from the OpsConfig.
    pub fn targets_from_config(config: &OpsConfig) -> Vec<KubeTarget> {
        let mut all: Vec<&TargetConfig> = Vec::new();
        all.extend(config.targets.as_deref().unwrap_or_default().iter());
        for project in &config.projects {
            for env in &project.environments {
                all.extend(env.targets.iter());
            }
        }
        all.into_iter()
            .filter(|t| t.connection_type == ConnectionType::Kubernetes)
            .map(|t| KubeTarget {
                name: t.name.clone(),
                kubeconfig: t.kubeconfig.clone(),
                context: t.context.clone(),
                default_namespace: t.namespace.clone(),
                autonomy: t.autonomy,
            })
            .collect()
    }

    fn resolve<'a>(&'a self, name: &str) -> Option<&'a KubeTarget> {
        self.config.targets.iter().find(|t| t.name == name)
    }

    fn audit(&self, target: &str, action: &str, detail: &str, duration_ms: u128, exit: i32) {
        let _ = write_audit_entry(
            target,
            &format!("kube {action} {detail}"),
            exit,
            duration_ms,
            self.audit_dir.as_ref(),
        );
    }
}

/// Valid Kubernetes DNS-1123 name check — reject shell metacharacters even
/// though we aren't shelling, to keep output predictable if we ever do.
fn is_valid_k8s_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

#[async_trait]
impl Tool for KubeTool {
    fn name(&self) -> &str {
        "kubernetes"
    }

    fn description(&self) -> &str {
        "Kubernetes cluster operations via the kube-rs client. Reads: \
         cluster_info, list_namespaces, list_pods, list_deployments, \
         list_services, list_nodes, logs (pod), events. Writes: \
         restart_deployment, scale_deployment, delete_pod. Writes respect \
         the target's autonomy level — DryRun rejects them. Every action \
         is audit-logged."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "configured k8s target name"},
                "action": {
                    "type": "string",
                    "enum": [
                        "cluster_info", "list_namespaces", "list_pods",
                        "list_deployments", "list_services", "list_nodes",
                        "logs", "events",
                        "restart_deployment", "scale_deployment", "delete_pod"
                    ]
                },
                "namespace": {"type": "string"},
                "name": {"type": "string", "description": "resource name"},
                "lines": {"type": "integer", "default": 200, "description": "logs tail"},
                "replicas": {"type": "integer", "description": "scale_deployment target"}
            },
            "required": ["target", "action"]
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let target_name = match args.get("target").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(kube_err("missing 'target'")),
        };
        let target = match self.resolve(target_name) {
            Some(t) => t,
            None => return Ok(kube_err(format!("unknown target '{target_name}'"))),
        };

        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Ok(kube_err("missing 'action'")),
        };

        let is_write = matches!(
            action,
            "restart_deployment" | "scale_deployment" | "delete_pod"
        );
        if is_write && target.autonomy == OpsClawAutonomy::DryRun {
            let detail = args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            self.audit(target_name, &format!("[blocked dry-run] {action}"), &detail, 0, -1);
            return Ok(kube_err(format!(
                "dry-run mode: write action '{action}' rejected"
            )));
        }

        let client = match self
            .factory
            .build(target.kubeconfig.as_deref(), target.context.as_deref())
            .await
        {
            Ok(c) => c,
            Err(e) => return Ok(kube_err(format!("kube client build failed: {e}"))),
        };

        let ns_default = target.default_namespace.as_deref();
        let namespace = args
            .get("namespace")
            .and_then(|v| v.as_str())
            .or(ns_default);

        let start = std::time::Instant::now();
        let result = self
            .dispatch(&client, action, namespace, &args)
            .await;
        let elapsed = start.elapsed().as_millis();
        let exit = match &result {
            Ok(r) if r.success => 0,
            _ => 1,
        };
        let detail = args
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        self.audit(target_name, action, &detail, elapsed, exit);
        result
    }
}

impl KubeTool {
    async fn dispatch(
        &self,
        client: &KubeClient,
        action: &str,
        namespace: Option<&str>,
        args: &Value,
    ) -> anyhow::Result<ToolResult> {
        match action {
            "cluster_info" => match client.cluster_version().await {
                Ok(v) => Ok(kube_ok(format!("version: {v}\n"))),
                Err(e) => Ok(kube_err(format!("{e}"))),
            },
            "list_namespaces" => match client.list_namespaces().await {
                Ok(nss) => {
                    let mut out = String::new();
                    writeln!(out, "count: {}", nss.len()).ok();
                    for n in nss {
                        writeln!(out, "  {n}").ok();
                    }
                    Ok(kube_ok(out))
                }
                Err(e) => Ok(kube_err(format!("{e}"))),
            },
            "list_pods" => match client.list_pods(namespace).await {
                Ok(pods) => {
                    let mut out = String::new();
                    writeln!(out, "count: {}", pods.len()).ok();
                    writeln!(out, "NS\tNAME\tREADY\tSTATUS\tRESTARTS\tNODE").ok();
                    for p in pods {
                        writeln!(
                            out,
                            "{}\t{}\t{}\t{}\t{}\t{}",
                            p.namespace, p.name, p.ready, p.status, p.restarts, p.node
                        )
                        .ok();
                    }
                    Ok(kube_ok(out))
                }
                Err(e) => Ok(kube_err(format!("{e}"))),
            },
            "list_deployments" => match client.list_deployments(namespace).await {
                Ok(deps) => {
                    let mut out = String::new();
                    writeln!(out, "count: {}", deps.len()).ok();
                    writeln!(out, "NS\tNAME\tREADY\tUP-TO-DATE\tAVAILABLE").ok();
                    for d in deps {
                        writeln!(
                            out,
                            "{}\t{}\t{}\t{}\t{}",
                            d.namespace, d.name, d.ready, d.up_to_date, d.available
                        )
                        .ok();
                    }
                    Ok(kube_ok(out))
                }
                Err(e) => Ok(kube_err(format!("{e}"))),
            },
            "list_services" => match client.list_services(namespace).await {
                Ok(svcs) => {
                    let mut out = String::new();
                    writeln!(out, "count: {}", svcs.len()).ok();
                    writeln!(out, "NS\tNAME\tTYPE\tCLUSTER-IP\tEXTERNAL-IP\tPORTS").ok();
                    for s in svcs {
                        writeln!(
                            out,
                            "{}\t{}\t{}\t{}\t{}\t{}",
                            s.namespace, s.name, s.svc_type, s.cluster_ip, s.external_ip, s.ports
                        )
                        .ok();
                    }
                    Ok(kube_ok(out))
                }
                Err(e) => Ok(kube_err(format!("{e}"))),
            },
            "list_nodes" => match client.list_nodes().await {
                Ok(nodes) => {
                    let mut out = String::new();
                    writeln!(out, "count: {}", nodes.len()).ok();
                    writeln!(out, "NAME\tSTATUS\tROLES\tVERSION").ok();
                    for n in nodes {
                        writeln!(out, "{}\t{}\t{}\t{}", n.name, n.status, n.roles, n.version).ok();
                    }
                    Ok(kube_ok(out))
                }
                Err(e) => Ok(kube_err(format!("{e}"))),
            },
            "logs" => {
                let name = match args.get("name").and_then(|v| v.as_str()) {
                    Some(n) if is_valid_k8s_name(n) => n,
                    Some(bad) => return Ok(kube_err(format!("invalid pod name '{bad}'"))),
                    None => return Ok(kube_err("logs requires 'name'")),
                };
                let ns = match namespace {
                    Some(n) => n,
                    None => return Ok(kube_err("logs requires 'namespace' (or a default)")),
                };
                let lines = args.get("lines").and_then(|v| v.as_i64()).unwrap_or(200);
                match client.get_pod_logs(ns, name, lines).await {
                    Ok(logs) => Ok(kube_ok(logs)),
                    Err(e) => Ok(kube_err(format!("{e}"))),
                }
            }
            "events" => match client.get_events(namespace).await {
                Ok(evts) => {
                    let mut out = String::new();
                    writeln!(out, "count: {}", evts.len()).ok();
                    for e in evts {
                        writeln!(
                            out,
                            "  {}  {}  {} — {}",
                            e.timestamp, e.reason, e.involved_object, e.message
                        )
                        .ok();
                    }
                    Ok(kube_ok(out))
                }
                Err(e) => Ok(kube_err(format!("{e}"))),
            },
            "restart_deployment" => {
                let name = match args.get("name").and_then(|v| v.as_str()) {
                    Some(n) if is_valid_k8s_name(n) => n,
                    Some(bad) => return Ok(kube_err(format!("invalid deployment name '{bad}'"))),
                    None => return Ok(kube_err("restart_deployment requires 'name'")),
                };
                let ns = match namespace {
                    Some(n) => n,
                    None => return Ok(kube_err("restart_deployment requires 'namespace'")),
                };
                match client.restart_deployment(ns, name).await {
                    Ok(()) => Ok(kube_ok(format!("restarted {ns}/{name}"))),
                    Err(e) => Ok(kube_err(format!("{e}"))),
                }
            }
            "scale_deployment" => {
                let name = match args.get("name").and_then(|v| v.as_str()) {
                    Some(n) if is_valid_k8s_name(n) => n,
                    Some(bad) => return Ok(kube_err(format!("invalid deployment name '{bad}'"))),
                    None => return Ok(kube_err("scale_deployment requires 'name'")),
                };
                let ns = match namespace {
                    Some(n) => n,
                    None => return Ok(kube_err("scale_deployment requires 'namespace'")),
                };
                let replicas = match args.get("replicas").and_then(|v| v.as_i64()) {
                    Some(r) if (0..=10_000).contains(&r) => r as i32,
                    _ => return Ok(kube_err("scale_deployment requires 'replicas' (0..=10000)")),
                };
                match client.scale_deployment(ns, name, replicas).await {
                    Ok(()) => Ok(kube_ok(format!("scaled {ns}/{name} to {replicas}"))),
                    Err(e) => Ok(kube_err(format!("{e}"))),
                }
            }
            "delete_pod" => {
                let name = match args.get("name").and_then(|v| v.as_str()) {
                    Some(n) if is_valid_k8s_name(n) => n,
                    Some(bad) => return Ok(kube_err(format!("invalid pod name '{bad}'"))),
                    None => return Ok(kube_err("delete_pod requires 'name'")),
                };
                let ns = match namespace {
                    Some(n) => n,
                    None => return Ok(kube_err("delete_pod requires 'namespace'")),
                };
                match client.delete_pod(ns, name).await {
                    Ok(()) => Ok(kube_ok(format!("deleted pod {ns}/{name}"))),
                    Err(e) => Ok(kube_err(format!("{e}"))),
                }
            }
            other => Ok(kube_err(format!("unknown action '{other}'"))),
        }
    }
}

fn kube_ok(mut s: String) -> ToolResult {
    if s.len() > KUBE_MAX_OUTPUT_BYTES {
        let mut cut = KUBE_MAX_OUTPUT_BYTES;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n... [truncated]");
    }
    ToolResult {
        success: true,
        output: s,
        error: None,
    }
}

fn kube_err<S: Into<String>>(msg: S) -> ToolResult {
    ToolResult {
        success: false,
        output: String::new(),
        error: Some(msg.into()),
    }
}

#[cfg(test)]
mod kube_tool_tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(is_valid_k8s_name("web-frontend"));
        assert!(is_valid_k8s_name("api.v1"));
        assert!(is_valid_k8s_name("nginx"));
    }

    #[test]
    fn invalid_names() {
        assert!(!is_valid_k8s_name(""));
        assert!(!is_valid_k8s_name("foo; rm"));
        assert!(!is_valid_k8s_name("foo|bar"));
        assert!(!is_valid_k8s_name("a b"));
    }

    #[test]
    fn tool_metadata() {
        let tool = KubeTool::new(KubeToolConfig { targets: vec![] });
        assert_eq!(tool.name(), "kubernetes");
        assert!(!tool.description().is_empty());
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["action"].is_object());
    }

    #[test]
    fn targets_from_config_filters_to_kubernetes_only() {
        let cfg: crate::ops_config::OpsConfig = toml::from_str(
            r#"
workspace_dir = "/tmp/x"

[[targets]]
name = "ssh-host"
type = "ssh"
host = "10.0.0.1"
user = "ops"

[[targets]]
name = "k8s-flat"
type = "kubernetes"
kubeconfig = "~/.kube/flat"
context = "ctx-flat"
namespace = "ns-flat"

[[targets]]
name = "local-box"
type = "local"
"#,
        )
        .expect("parses");

        let kts = KubeTool::targets_from_config(&cfg);
        assert_eq!(kts.len(), 1);
        assert_eq!(kts[0].name, "k8s-flat");
        assert_eq!(kts[0].kubeconfig.as_deref(), Some("~/.kube/flat"));
        assert_eq!(kts[0].context.as_deref(), Some("ctx-flat"));
        assert_eq!(kts[0].default_namespace.as_deref(), Some("ns-flat"));
    }

    #[test]
    fn targets_from_config_walks_flat_and_hierarchical() {
        let cfg: crate::ops_config::OpsConfig = toml::from_str(
            r#"
workspace_dir = "/tmp/x"

[[projects]]
name = "shopfront"

  [[projects.environments]]
  name = "prod"

    [[projects.environments.targets]]
    name = "k8s-prod"
    type = "kubernetes"
    context = "prod-ctx"

    [[projects.environments.targets]]
    name = "ssh-prod"
    type = "ssh"
    host = "10.0.0.1"
    user = "ops"
"#,
        )
        .expect("parses");

        let kts = KubeTool::targets_from_config(&cfg);
        assert_eq!(kts.len(), 1);
        assert_eq!(kts[0].name, "k8s-prod");
        assert_eq!(kts[0].context.as_deref(), Some("prod-ctx"));
    }

    #[test]
    fn targets_from_config_empty_when_no_kubernetes_targets() {
        let cfg = crate::ops_config::OpsConfig::default();
        assert!(KubeTool::targets_from_config(&cfg).is_empty());
    }

    #[tokio::test]
    async fn unknown_target_rejected() {
        let tool = KubeTool::new(KubeToolConfig { targets: vec![] });
        let r = tool
            .execute(json!({"target": "nope", "action": "list_pods"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unknown target"));
    }

    #[tokio::test]
    async fn dry_run_rejects_writes() {
        // We never build a real client in this test — the DryRun check
        // runs before the factory is invoked.
        let tool = KubeTool::new(KubeToolConfig {
            targets: vec![KubeTarget {
                name: "prod".into(),
                kubeconfig: None,
                context: None,
                default_namespace: Some("default".into()),
                autonomy: OpsClawAutonomy::DryRun,
            }],
        });
        let r = tool
            .execute(json!({
                "target": "prod", "action": "delete_pod",
                "namespace": "default", "name": "web-0"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("dry-run"));
    }

    #[tokio::test]
    async fn invalid_action() {
        // No factory needed — invalid action resolves after target/write gates
        // but requires a client build, which will fail; accept either error.
        let tool = KubeTool::new(KubeToolConfig {
            targets: vec![KubeTarget {
                name: "prod".into(),
                kubeconfig: Some("/nonexistent/kubeconfig".into()),
                context: None,
                default_namespace: None,
                autonomy: OpsClawAutonomy::Auto,
            }],
        });
        let r = tool
            .execute(json!({"target": "prod", "action": "nuke"}))
            .await
            .unwrap();
        assert!(!r.success);
    }

    fn auto_target() -> KubeTarget {
        KubeTarget {
            name: "prod".into(),
            kubeconfig: Some("/nonexistent/kubeconfig".into()),
            context: None,
            default_namespace: Some("default".into()),
            autonomy: OpsClawAutonomy::Auto,
        }
    }

    fn dry_target() -> KubeTarget {
        KubeTarget {
            name: "prod".into(),
            kubeconfig: None,
            context: None,
            default_namespace: Some("default".into()),
            autonomy: OpsClawAutonomy::DryRun,
        }
    }

    fn tool_with(target: KubeTarget) -> KubeTool {
        KubeTool::new(KubeToolConfig { targets: vec![target] })
    }

    #[tokio::test]
    async fn missing_target_arg() {
        let tool = tool_with(auto_target());
        let r = tool.execute(json!({"action": "list_pods"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("missing 'target'"));
    }

    #[tokio::test]
    async fn missing_action_arg() {
        let tool = tool_with(auto_target());
        let r = tool.execute(json!({"target": "prod"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("missing 'action'"));
    }

    #[tokio::test]
    async fn dry_run_rejects_restart_deployment() {
        let tool = tool_with(dry_target());
        let r = tool
            .execute(json!({
                "target": "prod", "action": "restart_deployment",
                "namespace": "default", "name": "api"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        let err = r.error.unwrap();
        assert!(err.contains("dry-run"));
        assert!(err.contains("restart_deployment"));
    }

    #[tokio::test]
    async fn dry_run_rejects_scale_deployment() {
        let tool = tool_with(dry_target());
        let r = tool
            .execute(json!({
                "target": "prod", "action": "scale_deployment",
                "namespace": "default", "name": "api", "replicas": 3
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("dry-run"));
    }

    #[tokio::test]
    async fn dry_run_allows_reads_but_client_build_fails() {
        // DryRun does not block list_pods; the failing kubeconfig surfaces as a
        // client-build error rather than a dry-run block.
        let mut t = dry_target();
        t.kubeconfig = Some("/nonexistent/kubeconfig".into());
        let tool = tool_with(t);
        let r = tool
            .execute(json!({"target": "prod", "action": "list_pods"}))
            .await
            .unwrap();
        assert!(!r.success);
        let err = r.error.unwrap();
        assert!(err.contains("kube client build failed"));
        assert!(!err.contains("dry-run"));
    }

    #[tokio::test]
    async fn auto_mode_surfaces_client_build_error() {
        // Auto lets the call reach the factory, which fails on the bad path —
        // proves writes are not silently dropped under Auto.
        let tool = tool_with(auto_target());
        let r = tool
            .execute(json!({
                "target": "prod", "action": "delete_pod",
                "namespace": "default", "name": "web-0"
            }))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("kube client build failed"));
    }

    // NOTE: per-action argument validation (invalid name, out-of-range
    // replicas, missing namespace/pod name) is implemented inside
    // `dispatch`, which runs *after* `factory.build()`. In fast unit
    // tests with a bogus kubeconfig the client-build error masks the
    // more specific validation error. Covering those messages requires
    // either (a) restructuring execute() to validate before building or
    // (b) wiring a working fake KubeClientFactory. Both are out of
    // scope for the fast-test pass. The dry-run and auto-with-bad-config
    // tests above still prove the important property: writes either
    // get blocked in DryRun or surface a structured error in Auto —
    // never silently succeed.
}
