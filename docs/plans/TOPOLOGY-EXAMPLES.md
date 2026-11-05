# Topology graph — worked examples

These examples show what the proposed model would look like. Example names
come from the kube contexts and the sandbox config. Namespaces, workloads
and dependencies are made-up examples, not discovered facts.

## 1. Example, declared in config

You declare only what OpsClaw can't discover: environments, connection
boundaries, credentials and access paths.

```toml
[[node]]
urn = "urn:opsclaw:example"
kind = "project"
autonomy = "observe"

# The hub is an environment of its own: the place OpsClaw works from.
[[node]]
urn = "urn:opsclaw:example:hub"
kind = "environment"

[[node]]
urn = "urn:opsclaw:example:hub:jumpbox"
kind = "machine"
connection = "local"            # OpsClaw runs here

[[node]]
urn = "urn:opsclaw:example:sandbox"
kind = "environment"
autonomy = "suggest"            # sandbox may propose fixes

[[node]]
urn = "urn:opsclaw:example:sandbox:aks"
kind = "cluster"
credential = "store:sandbox-kubeconfig"
discover = true                 # namespaces, workloads, nodes come from the API

[[node]]
urn = "urn:opsclaw:example:staging"
kind = "environment"            # inherits observe from the project

[[node]]
urn = "urn:opsclaw:example:staging:aks"
kind = "cluster"
credential = "store:staging-kubeconfig"
discover = true

# A managed service with no cluster or machine: straight under the environment.
[[node]]
urn = "urn:opsclaw:example:staging:servicebus"
kind = "service"
type = "azure_service_bus"
credential = "store:staging-sb"

[[edge]]
from = "urn:opsclaw:example:sandbox:aks"
to = "urn:opsclaw:example:hub:jumpbox"
kind = "reached_via"

[[edge]]
from = "urn:opsclaw:example:staging:aks"
to = "urn:opsclaw:example:hub:jumpbox"
kind = "reached_via"
```

## 2. The tree after discovery

Lines marked `*` are discovered. The rest are declared.

```
example                                   project      observe
├── hub                                   environment
│   └── jumpbox                           machine      (OpsClaw runs here)
├── sandbox                               environment  suggest
│   └── aks                               cluster      kubeconfig: sandbox
│       ├── * node/aks-system-0           k8s node
│       ├── * logs                        namespace
│       │   └── * coresearch-es           statefulset  → elasticsearch
│       ├── * monitoring                  namespace
│       │   └── * prometheus-stack        deployment   → prometheus
│       └── * app                         namespace
│           ├── * example-api             deployment
│           └── * eventstore              statefulset  → eventstore
└── staging                               environment  (observe, inherited)
    ├── aks                               cluster      kubeconfig: staging
    │   └── * …
    └── servicebus                        service      azure_service_bus
```

Levels are skipped where they don't apply. `servicebus` has no cluster or
machine. A single VPS would sit directly under its environment (example 6).

## 3. Identifiers: URNs of values only

Every node has a URN made only of names, outermost first:

```
urn:opsclaw:example:sandbox:aks                          the cluster (today's "target")
urn:opsclaw:example:sandbox:aks:app                      a namespace
urn:opsclaw:example:sandbox:aks:app:example-api          a workload
urn:opsclaw:example:sandbox:aks:logs:coresearch-es       ES (also an elasticsearch resource)
urn:opsclaw:example:staging:servicebus                   a managed service, no cluster
urn:opsclaw:example:hub:jumpbox                          a machine directly in an environment
urn:opsclaw:homelab:prod:nas
```

The URN is an **address, not a description**. You can't tell a segment's
kind from its position, and nothing tries to. The kind, the OpenTelemetry
attributes (`k8s.namespace.name=app`, …) and the policy all live on the node
the URN resolves to. Tools and the UI show the kind next to the URN, e.g.
`…:aks:app` (namespace).

The rules that make this safe:

1. **Sibling names are unique across kinds**, as in a filesystem. A machine
   and a cluster can't both be called `aks` in `staging`.
   - Kubernetes allows a Deployment and a StatefulSet with the same name in
     one namespace. That's rare; discovery reports it, and the second one
     gets a kind suffix (`redis.sts`).
   - Services aren't tree nodes. A Service is a `depends_on` target and an
     attribute of the workloads it selects, so it never clashes with the
     Deployment of the same name, which is very common.
2. **Containment is a segment prefix.** "Is this node under staging?" is a
   prefix check on `urn:opsclaw:example:staging:`, comparing whole segments
   so that `staging` doesn't match `staging2`. Scope checks stay cheap and
   need no graph lookup.
3. **The project and environment are always the first two segments**, so
   the environment level is mandatory.
4. **No `:` in names.** Kubernetes names can't contain it, and config
   validation rejects it in names you declare.
5. **A stable node id sits underneath.** If a node moves (say a cluster
   level is added later), its URN changes but its id doesn't. The audit log
   stores both, so history doesn't split.

**Legacy paths.** Today's `project::env::target` is already values-only. It
becomes `urn:opsclaw:project:env:target` with no lookup needed. The old
`::rtype::name` resource suffix becomes a child segment. Old audit rows are
read as they are, so no applied migration changes.

**Registration.** The `opsclaw` namespace id isn't registered with IANA.
That's fine for internal ids; register it only if other systems ever need to
quote these URNs.

The audit log records the node a command acted on, not just the cluster:

```
2026-11-05T09:12Z  agent  kubectl logs --previous example-api-7f9c  urn:opsclaw:example:sandbox:aks:app:example-api  read   allowed
2026-11-05T09:13Z  agent  kubectl rollout restart example-api       urn:opsclaw:example:staging:aks:app:example-api  write  blocked (observe)
```

## 4. Policy inheritance

Autonomy, expected state and scope pass down the tree, and the nearest
ancestor that sets one wins.

| Node | Autonomy | Why |
|---|---|---|
| `urn:opsclaw:example:staging:aks:app:example-api` | observe | inherited from the project |
| `urn:opsclaw:example:sandbox:aks:app:example-api` | suggest | set on `sandbox` |
| `urn:opsclaw:example:sandbox:aks:kube-system` | observe | config can pin a namespace lower |

**Scope follows the node.** A namespace-scoped credential attaches to the
`app` namespace node. OpsClaw then refuses, before calling the API server,
any command that resolves to another namespace. Today that check exists only
as a target-wide `KubernetesScope`.

## 5. Edges, and how diagnosis uses them

Discovered edges come from the API. Declared edges come from config.

```
example-api       depends_on   eventstore        (discovered: env var / service DNS)
example-api       depends_on   servicebus        (declared: managed service)
example-api       runs_on      node/aks-user-3   (discovered: pod placement)
coresearch-es     reached_via  port-forward → urn:opsclaw:example:sandbox:aks
sandbox:aks       reached_via  hub:jumpbox
```

An alert says `example-api 5xx high`. The agent:

1. Checks `example-api`'s own recent changes (rollouts, config).
2. Follows `depends_on` and checks `eventstore` and `servicebus`.
3. Follows `runs_on` and checks `node/aks-user-3`, which shows memory
   pressure.
4. Checks the node's other workloads. `eventstore` is on the same node, so
   both symptoms point at one cause.

It reports: "Likely cause: node `aks-user-3` memory pressure. It evicted
`eventstore` pods, and `example-api` errors follow. Evidence: …"

Today the agent has to rebuild those links from `kubectl` output every time,
and loses them when the history is trimmed.

## 6. Small users

A homelab with no cluster, where the machine sits straight under the
environment:

```
homelab               project
└── prod              environment
    ├── nas           machine     ssh
    └── pihole        machine     ssh
```

A single VPS still gets an environment, because that level is mandatory
(§3):

```
blog                  project
└── prod              environment
    └── vps           machine     ssh     urn:opsclaw:blog:prod:vps
```

## 7. What the agent can ask

A `topology` tool answers from the stored graph without running `kubectl`:

```
topology(path="urn:opsclaw:example:sandbox:aks:app:example-api", depth=1)
→ example-api  deployment  3/3 ready
    depends_on: eventstore (statefulset, 1/1), servicebus (azure_service_bus)
    runs_on:    aks-user-1, aks-user-3
    changed:    image 1.42.0 → 1.43.0 at 08:55Z
```

This also covers change correlation (`recent_changes`, DIAGNOSIS.md item 3).
The graph is where changes get attached.

## Open questions

1. ~~Can a project hold machines directly, with no environment?~~ Decided
   in §3: the environment level is mandatory. A lone VPS gets an
   environment such as `urn:opsclaw:blog:prod:vps`.
2. How often should discovery refresh? Per heartbeat tick is cheap for the
   kube API and keeps the graph fresh.
3. Should inferred `depends_on` edges (from env vars and service DNS) be
   trusted, or only shown as hints next to declared ones?
