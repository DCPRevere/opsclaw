# Kubernetes

OpsClaw can monitor and remediate Kubernetes clusters as a first-class target type.

## Target configuration

```toml
[[targets]]
name = "prod-k8s"
type = "kubernetes"
kubeconfig = "/path/to/kubeconfig"  # Optional; see resolution order below
namespace = "default"               # Optional; omit to monitor all namespaces
autonomy = "supervised"
context_file = "~/.opsclaw/context/prod-k8s.md"
```

### Kubeconfig resolution

1. `kubeconfig` key in `opsclaw.toml` (explicit path)
2. In-cluster config (when OpsClaw itself runs inside a pod)
3. `~/.kube/config`

## Discovery

Run a full cluster discovery scan:

```bash
opsclaw scan prod-k8s
```

This discovers and snapshots:

- Cluster version and API server info
- All namespaces
- Pods — status, restart counts, container images
- Deployments — replica counts, rollout status
- Services — types, ports, selectors
- Nodes — capacity (CPU, memory), conditions (Ready, MemoryPressure, etc.)
- Recent events — warnings and errors across all namespaces

Results are saved to `~/.opsclaw/snapshots/prod-k8s.json`.

## What OpsClaw monitors

During continuous monitoring (`opsclaw monitor` or daemon), OpsClaw watches for:

- Pods in `CrashLoopBackOff` or `OOMKilled`
- Deployments with unavailable replicas
- Nodes in `NotReady`
- PersistentVolumeClaims stuck in `Pending`
- High pod restart counts
- Warning events (e.g. `BackOff`, `FailedScheduling`, `Unhealthy`)

## Remediation actions

With appropriate autonomy level, OpsClaw can:

- **Restart a deployment** — equivalent to `kubectl rollout restart`
- **Scale a deployment** — adjust replica count
- **Retrieve pod logs** — for diagnosis
- **Describe a pod** — events, conditions, resource requests
- **Delete a stuck pod** — allows it to reschedule

All actions are logged to the audit trail at `~/.opsclaw/audit/`.

## RBAC

When running OpsClaw outside the cluster (the most common setup), your kubeconfig's user needs sufficient permissions. A minimal read+remediator ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: opsclaw
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "nodes", "namespaces", "events", "services", "persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs: ["get", "list", "watch", "update", "patch"]
```

Bind to your service account:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: opsclaw
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: opsclaw
subjects:
  - kind: User
    name: opsclaw
    apiGroup: rbac.authorization.k8s.io
```

## In-cluster deployment

If you want OpsClaw to run as a pod inside the cluster it monitors, use a ServiceAccount with the ClusterRole above and omit `kubeconfig` from the config — it will use the mounted service account token automatically.

Example deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opsclaw
  namespace: opsclaw
spec:
  replicas: 1
  selector:
    matchLabels:
      app: opsclaw
  template:
    metadata:
      labels:
        app: opsclaw
    spec:
      serviceAccountName: opsclaw
      containers:
        - name: opsclaw
          image: opsclaw:latest
          args: ["daemon"]
          env:
            - name: OPSCLAW_PROVIDER
              value: openrouter
            - name: OPSCLAW_API_KEY
              valueFrom:
                secretKeyRef:
                  name: opsclaw-secrets
                  key: api-key
```

## Context files

Add cluster-specific knowledge to `~/.opsclaw/context/prod-k8s.md` to help OpsClaw make better decisions:

```markdown
# prod-k8s context

This cluster runs the main customer-facing API. The `api` namespace is revenue-critical.

Deployments in `api` must not be restarted during business hours (09:00–18:00 UTC)
unless there is active data loss or complete outage.

The `worker` namespace jobs are idempotent and can be freely restarted.

Known flaky pods: `billing-cron-*` sometimes fails on startup due to a slow DB connection.
Restart once before escalating.
```

## Multiple clusters

Add one target per cluster:

```toml
[[targets]]
name = "prod-k8s"
type = "kubernetes"
kubeconfig = "~/.kube/prod"
autonomy = "supervised"

[[targets]]
name = "staging-k8s"
type = "kubernetes"
kubeconfig = "~/.kube/staging"
autonomy = "full"
```
