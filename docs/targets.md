# Targets

A **Target** is the bottom level of the OpsClaw hierarchy. It is one addressable endpoint — one set of credentials, one connection type, one audit identity. Targets are what the agent actually opens sessions against.

> For the levels above this one, see [projects.md](projects.md) and [environments.md](environments.md). For the overall model, see [hierarchy.md](hierarchy.md).

## What a Target is

A Target is a single thing the agent connects to. The test is concrete:

> If you would need a different set of credentials or a different API endpoint to talk to it, it is a different Target.

One Target, one credential set, one audit log identity. Always.

## What a Target is not

- Not a process, service, pod, container, or deployment. Those are runtime state, discovered *through* a Target.
- Not a tier. Tiers are Environments.
- Not a product. Products are Projects.

## Connection types

| Type | What it represents | Key fields |
|---|---|---|
| `ssh` | A remote host reachable over SSH. | `host`, `port`, `user`, `key_secret` |
| `local` | The machine OpsClaw itself runs on. | (none) |
| `kubernetes` | A cluster API endpoint. | `kubeconfig`, `context`, `namespace` |

Future connection types slot in by adding an enum variant — the Environment/Project structure stays untouched.

## One Environment, many Targets

An Environment almost always holds many Targets. Real prods are never one box. Examples:

**Classic three-tier**
```
shopfront/prod/
  web-1, web-2, web-3             # SSH
  api-1, api-2                    # SSH
  db-primary, db-replica          # SSH
  redis                           # SSH
```

**Kubernetes plus adjacent infrastructure**
```
data-platform/prod/
  eks-main                        # Kubernetes
  eks-dr                          # Kubernetes (disaster recovery)
  bastion                         # SSH
  airflow-vm                      # SSH (legacy, not yet migrated)
```

**Multi-region**
```
api-gateway/prod/
  gw-us-east-1, gw-us-west-2, gw-eu-west-1, gw-ap-south-1
```

Region is a naming convention on Targets, not its own hierarchy level — escalation and autonomy do not vary by region, so it would be a level without a policy job to do.

## Kubernetes Targets

A Kubernetes Target is **the cluster API endpoint**, not the cluster's workload. One kubeconfig context = one Target.

```
[[targets]]
name = "prod-eks"
type = "kubernetes"
kubeconfig = "~/.kube/prod-eks"
context = "prod-us-east"
namespace = "default"
```

The same physical cluster can appear as two Targets in two Environments if namespaces differ:

```
staging/shared-cluster   namespace = staging
prod/shared-cluster      namespace = prod
```

Pods, deployments, nodes (as k8s sees them), services, CRDs — all runtime state, discovered through the cluster Target. Never configured as Targets.

## Nodes under a Kubernetes cluster

A Kubernetes worker or control-plane node becomes a **separate Target** only when you actually SSH into it and that SSH access is part of your operational repertoire.

- **Managed k8s (EKS, GKE, AKS)** — you cannot SSH into workers. Nodes are not Targets. Everything node-level happens via the k8s API.
- **Self-managed k8s on your own VMs** — you SSH in for kubelet, disk, containerd, network debugging. Nodes **are** Targets.
- **Bare-metal / on-prem / k3s / edge** — nodes are Targets and often need hardware-level tools.

When nodes are Targets, they are **siblings** of the cluster Target under the Environment, not children of it. They are different lenses on the same infrastructure:

```
platform/prod/
  prod-cluster        Kubernetes   - "what does k8s think?"
  worker-01..03       SSH          - "what does the OS think?"
  control-plane-1     SSH          - privileged, narrower autonomy
```

Debugging `NotReady` nodes routinely needs both views. The disagreement between them is often the bug.

## What belongs on a Target

| Field | Purpose |
|---|---|
| `name` | Unique within the Environment. Used in addresses and audit logs. |
| `type` | `ssh`, `local`, or `kubernetes`. |
| Connection fields | Type-specific: `host`/`port`/`user`/`key_secret` for SSH, `kubeconfig`/`context`/`namespace` for Kubernetes. |
| `role` | Optional tag: `worker`, `control-plane`, `bastion`, `db`. Used by autonomy and escalation policies. |
| `autonomy` | Optional override of the Environment's autonomy. Rare; flag loudly in review. |
| `context_file` | Markdown prepended to the agent's prompt for operations on this Target. |
| `probes` | External health probes (HTTP, TCP, DNS, TLS cert). Target-scoped because probes describe the Target itself. |
| `data_sources` | Pull-based sources unique to this Target (a per-host Seq instance, a Target-specific GitHub repo). Shared pools live on the Environment. |

## What does not belong on a Target

- Tier-wide policy (autonomy default, escalation, notification routing) — lives on the Environment.
- Product-wide context — lives on the Project.
- Shared endpoint pools (Loki, ELK, Prometheus, PagerDuty) — Environment-scoped.
- Workloads running on the Target — runtime state, not config.

## Credentials and blast radius

Each Target holds its own credentials. They do not inherit from the Environment. If two Targets legitimately share a key, they reference the same named secret — they do not share a field. This keeps the blast radius of a leaked key equal to the Targets that explicitly reference it, no more.

## Dynamic discovery (future)

For self-managed k8s with fifty workers, declaring every node statically gets painful. A future `ssh-pool` Target type can describe the *shape* of many SSH connections, discovered dynamically via a cluster Target:

```
[[targets]]
name = "prod-workers"
type = "ssh-pool"
discovered_from = "prod-cluster"
selector = "role=worker"
ssh_template = { user = "sre", key_secret = "worker-ssh-key", host = "{{node.InternalIP}}" }
```

The audit log records the actual node name at call time. Autonomy applies uniformly. Not built yet — mentioned here so the Target schema reserves room for it without a breaking change.

## Addressing

Targets are addressed by `project/environment/target`, with the usual shortenings when unambiguous:

```
shopfront/prod/web-1
prod/web-1              # if only one project
web-1                   # if only one project and one environment
```

The audit log always records the fully qualified form.

## See also

- [hierarchy.md](hierarchy.md) — the full model
- [projects.md](projects.md) — the level above
- [environments.md](environments.md) — the policy level above
- [k8s.md](k8s.md) — Kubernetes-specific guidance
- [autonomy.md](autonomy.md) — how autonomy is resolved
