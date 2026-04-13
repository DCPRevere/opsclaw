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
use tracing::{debug, warn};

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
    async fn build(&self, kubeconfig: Option<&str>) -> Result<KubeClient>;
}

/// Default factory that creates a real client from the environment or a
/// specific kubeconfig path.
pub struct DefaultKubeClientFactory;

#[async_trait::async_trait]
impl KubeClientFactory for DefaultKubeClientFactory {
    async fn build(&self, kubeconfig: Option<&str>) -> Result<KubeClient> {
        KubeClient::new(kubeconfig).await
    }
}

impl KubeClient {
    /// Create a new client.
    ///
    /// If `kubeconfig` is `Some`, that path is used; otherwise the default
    /// kubeconfig resolution order applies (~/.kube/config, in-cluster).
    pub async fn new(kubeconfig: Option<&str>) -> Result<Self> {
        let config = match kubeconfig {
            Some(path) => {
                let kubeconfig = kube::config::Kubeconfig::read_from(path)
                    .context("failed to read kubeconfig")?;
                kube::Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
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
        let cluster_info = self.cluster_version().await.unwrap_or_else(|e| {
            warn!(error = %e, "Failed to retrieve cluster version");
            String::new()
        });
        let namespaces = self.list_namespaces().await.unwrap_or_else(|e| {
            warn!(error = %e, "Failed to list namespaces");
            Vec::new()
        });
        let pods = self.list_pods(None).await.unwrap_or_else(|e| {
            warn!(error = %e, "Failed to list pods");
            Vec::new()
        });
        let deployments = self.list_deployments(None).await.unwrap_or_else(|e| {
            warn!(error = %e, "Failed to list deployments");
            Vec::new()
        });
        let services = self.list_services(None).await.unwrap_or_else(|e| {
            warn!(error = %e, "Failed to list services");
            Vec::new()
        });
        let nodes = self.list_nodes().await.unwrap_or_else(|e| {
            warn!(error = %e, "Failed to list nodes");
            Vec::new()
        });
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

    async fn cluster_version(&self) -> Result<String> {
        let version = self.client.apiserver_version().await?;
        Ok(format!("v{}.{}", version.major, version.minor))
    }

    async fn list_namespaces(&self) -> Result<Vec<String>> {
        let ns_api: Api<Namespace> = Api::all(self.client.clone());
        let list = ns_api.list(&ListParams::default()).await?;
        Ok(list
            .items
            .iter()
            .filter_map(|ns| ns.metadata.name.clone())
            .collect())
    }

    async fn list_pods(&self, namespace: Option<&str>) -> Result<Vec<K8sPod>> {
        let pods: Api<Pod> = match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let list = pods.list(&ListParams::default()).await?;
        Ok(list.items.into_iter().map(pod_to_snapshot).collect())
    }

    async fn list_deployments(&self, namespace: Option<&str>) -> Result<Vec<K8sDeployment>> {
        let deps: Api<Deployment> = match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let list = deps.list(&ListParams::default()).await?;
        Ok(list.items.into_iter().map(deployment_to_snapshot).collect())
    }

    async fn list_services(&self, namespace: Option<&str>) -> Result<Vec<K8sService>> {
        let svcs: Api<Service> = match namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let list = svcs.list(&ListParams::default()).await?;
        Ok(list.items.into_iter().map(service_to_snapshot).collect())
    }

    async fn list_nodes(&self) -> Result<Vec<K8sNode>> {
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
