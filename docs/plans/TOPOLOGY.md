# Topology: a graph of what OpsClaw watches

Status: design, not built. The worked examples are in
[TOPOLOGY-EXAMPLES.md](TOPOLOGY-EXAMPLES.md).

## Problem

Today every target sits at a fixed `project::env::target` path. A target is
anything OpsClaw holds one credential for: an SSH host, the local machine, a
whole Kubernetes cluster, a cloud account. This causes three problems:

1. **A cluster is treated as one opaque machine.** Its namespaces,
   workloads and nodes aren't in the model. Policy can only scope by the
   `namespace` in the target's credential. The audit log only records
   "the cluster".
2. **Nothing records relationships.** You can't say "ES runs inside this
   cluster", "the app depends on Service Bus" or "these spokes are reached
   via the hub jumpbox". The agent rebuilds that from `kubectl` output each
   turn, then loses it when the history is trimmed.
3. **The fixed depth doesn't fit real estates.** A managed service has no
   cluster or machine. A homelab machine belongs straight to an environment.

Diagnosis needs the relationships most; that's DIAGNOSIS.md item 2
(dependency map) and item 3 (change correlation). This design is the
foundation for both.

## Model

### Nodes

A node has a stable `id` (UUID), a `kind`, a `name`, a parent, attributes
and a source (`declared` or `discovered`).

| Rank | Kinds | Declared or discovered |
|---|---|---|
| 0 | `project` | declared |
| 1 | `environment` | declared |
| 2 | `machine`, `cluster`, `service`, `cloud` | declared |
| 3 | `node` (k8s), `namespace` | discovered |
| 4 | `workload` (deployment, statefulset, daemonset, cronjob, job) | discovered |
| 5 | `pod` | discovered, short-lived (see Discovery) |

**Containment is a tree.** Every node except a project has exactly one
parent, which must rank lower than the node itself. Levels can be skipped
anywhere below the environment, so a `service` or `machine` can sit straight
under an environment. Project and environment are mandatory.

One parent per node is deliberate. Autonomy, expected state and scope pass
down containment, and two parents would make that ambiguous.

**Attributes** use OpenTelemetry resource conventions where one exists:
`deployment.environment.name`, `k8s.cluster.name`, `k8s.namespace.name`,
`k8s.deployment.name`, `k8s.pod.name`, `k8s.node.name`, `host.name`,
`service.name`, `cloud.provider`, `cloud.region`, `cloud.resource_id`. A
node then matches its own telemetry (Prometheus labels, ES/Loki fields)
without translation. OpsClaw-only attributes go under `opsclaw.*`, such as
`opsclaw.resource_type = "elasticsearch"`.

**Resources** (Elasticsearch, Postgres, Service Bus, …) are no longer a
separate fifth path segment. A resource is a node with a
`opsclaw.resource_type`:
- either declared under the environment as a `service`;
- or discovered as a workload, with the type added by config or by an
  annotation match.

### Edges

Edges are directed, typed, and never carry policy.

| Kind | Meaning | Source |
|---|---|---|
| `depends_on` | A needs B to work | declared; or inferred from Service DNS / env vars (marked `inferred`) |
| `runs_on` | a pod or workload is placed on a k8s node or machine | discovered |
| `reached_via` | connecting to A goes through B (jumpbox, port-forward) | declared |
| `selects` | a k8s Service routes to a workload | discovered |

Inferred edges are shown to the agent as hints ("probably depends on"),
never as facts. That settles open question 3 in the examples doc.

### Connections and credentials

A credential attaches to a **connection boundary**: a `machine`,
`cluster`, `service` or `cloud`. Its children use the boundary's connection,
so a namespace runs commands through its cluster's kubeconfig.

Scope moves from the target to the node. A namespace-scoped credential is
declared on the `namespace` node, and policy blocks any command that
resolves to a different node before it reaches the API server.

`reached_via` replaces `jump_host` and the port-forward conventions
(DESIGN §4 placement): the executor builds the connection by walking the
edges.

## Identifiers

Every node has a URN of values only, outermost first:

```
urn:opsclaw:<project>:<environment>[:<name>…]
```

The rules are in TOPOLOGY-EXAMPLES.md §3. In short:

- The URN is an address, not a description. You can't tell a segment's
  kind from its position; the kind lives on the node.
- Sibling names are unique across kinds.
- Containment is a whole-segment prefix match.
- Names contain no `:`.
- Kubernetes Services aren't tree nodes, so they never clash with the
  Deployment of the same name.

**Where the id and the URN are used:**
- The UUID is what's stored on audit rows, incidents and approvals, so a
  node that moves keeps its history.
- The URN is what humans, the model and config use.
- Audit rows store both: the UUID and the URN at the time.

**Legacy.** `project::env::target` maps to `urn:opsclaw:project:env:target`,
and `…::rtype::name` becomes a child segment. Old rows are read as they are,
and new rows use the URN. `FqTarget` becomes a thin wrapper over a node URN
during the move (see Phases).

## Config

```toml
[[node]]
urn = "urn:opsclaw:example:sandbox:aks"
kind = "cluster"
credential = "store:sandbox-kubeconfig"
discover = true
autonomy = "suggest"          # optional, inherits otherwise

[[edge]]
from = "urn:opsclaw:example:sandbox:aks"
to = "urn:opsclaw:example:hub:jumpbox"
kind = "reached_via"
```

- **Parents** come from the URN: the longest declared prefix.
- **Validation:** a missing parent, a parent of equal or higher rank, a
  duplicate sibling name or a `:` in a name are all boot errors.
- **The old format still works.** `[[project]]` / `[[project.env]]` /
  `[[project.env.target]]` files are translated to nodes at load time with
  the same meaning: `kind = "kubernetes"` → `cluster`, `ssh` / `local` →
  `machine`, `cloud` → `cloud`, and each resource → a child `service`. No
  existing config breaks. `opsclaw-cli config migrate` can rewrite a file to
  the new format.

## Discovery

- **When:** a discovery pass runs per `discover = true` boundary on each
  heartbeat tick. The Kubernetes API list calls are cheap at Example's
  scale.
- **What it reads:** namespaces, nodes, workloads, Services (for `selects`)
  and pod placement (for `runs_on`).
- **Storage:** results go in new tables, `topology_nodes` and
  `topology_edges` (a new migration; the applied ones are untouched). Each
  row records `first_seen` and `last_seen`.
- **Disappearance:** a node not seen for N passes is marked gone, not
  deleted. History and incidents still point at it.
- **Pods are not persisted as nodes.** They churn too much. Placement and
  restart counts are summarised onto their workload; a pod URN is resolved
  live when a command targets one.
- **Changes:** each pass diffs workloads against the previous snapshot and
  records changes such as image, replicas and spec generation in
  `topology_changes`. That's DIAGNOSIS.md item 3 (`recent_changes`),
  arriving almost for free.

## Policy

- **Autonomy and expected state:** the nearest ancestor that sets one wins,
  as now, but over any depth.
- **Scope:** checked by URN prefix before the command runs.
  `kubernetes:delete` on a node outside the credential's subtree is
  blocked, and the block is audited.
- **Command classification and the policy choke point don't change.**
  `policy::execute` still sees every command; it just receives a node rather
  than a fixed target.
- **The heartbeat registry** still filters by tool, unchanged.

## Agent surface

- **`topology(urn, depth)`** — a node, its children to `depth`, its edges and
  its recent changes, from the stored graph with no command executed. It's
  read-only, so it runs concurrently with other reads.
- **Tool `target` arguments** accept a node URN anywhere a target path is
  accepted today. The tool resolves its connection boundary by walking up
  the tree.
- **Prompt:** the scan checklist's workload sweep can start from the stored
  graph and confirm live, rather than re-listing everything each time.

## Phases

1. **Model and identifiers, no behaviour change.** Add node, edge and URN
   types; translate the existing config into nodes; give `FqTarget` the
   URN form, still parsing `::` paths; write the URN and node UUID on new
   audit rows. Every existing test passes unchanged.
2. **Config.** Add `[[node]]` and `[[edge]]`, and `config migrate`. Scope
   moves from target to node.
3. **Discovery and storage** for Kubernetes: the migration, the discovery
   pass, `topology_changes`, and the `topology` tool.
4. **Edges in diagnosis.** `reached_via` drives connection building,
   replacing `jump_host`. Inferred `depends_on` edges appear as hints. The
   scan prompt uses the graph.
5. **More discovery:** Azure (resource groups, managed services via
   `cloud.resource_id`) and machines (systemd units, containers).

Phase 1 is the riskiest refactor (`FqTarget` appears in about 30 files),
but it changes no behaviour, so the existing suite is the safety net.

## Open questions

1. Should discovery also run during an interactive turn when the graph is
   stale, or only on heartbeat ticks?
2. Should an annotation (`opsclaw.dev/resource-type: elasticsearch`) be the
   way a workload becomes a typed resource, or should only config do that?
3. Retention for `topology_changes`: keep 30 days, or as long as incidents
   reference them?
