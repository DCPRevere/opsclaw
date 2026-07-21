# Remundo — Reference Deployment Profile

What opsclaw must manage first. Distilled from a survey of `~/src/remundo`
(2026-07-21); the docs listed at the end are the authoritative sources. This
drives the v1 tool set (DESIGN.md §4) and the eval/runbook seed material.

## The system in one paragraph

.NET/Azure event-sourced microservices (~50 `Remundo.*` services) on AKS.
Commands arrive via **Azure Service Bus** queues (raw SDK, no MassTransit —
retry semantics are hand-rolled per service; DLQs are the standard failure
path); domain services append events to **KurrentDB** (EventStoreDB
successor, self-hosted in-cluster, **mid-migration to a 3-shard topology**
with switchover/restore jobs staged); `Remundo.Synchroniser` (~55 catch-up
subscriptions, replicas=1) projects events into **Elasticsearch** read
models, which the UI/API reads. Logs ship via Filebeat into the same
Elasticsearch (NLog, ECS fields) — there is no Loki. Metrics:
kube-prometheus-stack. Errors: Sentry. Deploys are **GitOps**: GitHub
Actions builds → GHCR → a bot commit bumps the image tag in `Remundo.Iac` →
ArgoCD syncs; nothing ever `kubectl apply`s. Cloud infra: Terraform via
Azure DevOps pipelines. KEDA autoscales workers off Service Bus queue depth.
No Redis, no app Postgres, no Cosmos.

## Environments and clusters

| Env | Cluster | Notes |
|---|---|---|
| dev | `aks-dev-spoke04-clus01` | dev subscription |
| sandbox | `aks-sandbox-spoke05-clus01` | **normally stopped** (API FQDN NXDOMAIN = stopped, not creds); data **wiped monthly** by design; lives in the prod subscription |
| staging + prod | `spoke01-clus01-k8s` | **one physical cluster**, namespace-separated only |

All access goes through a jumpbox (`ukazjb-000007003`) behind Azure
Bastion — opsclaw's intended home (adjacent placement, DESIGN.md §5).

Modelling: staging and prod become **two opsclaw Targets** over the same
cluster with distinct namespace-scoped ServiceAccount kubeconfigs.
Terraform env names (`dev/staging/preprod/prod`) and Kustomize overlay names
(`dev/sandbox/prod` + tenant overlays: xml, ecolab, airbnb, upwork, …) do
**not** map 1:1 — record the mapping in target config, not in the agent's
head. ArgoCD versions differ per cluster (v3.0.1 dev, v2.14.2 sandbox) —
check version-sensitive behaviour per cluster.

## What on-call actually touches

- **DLQ backlog** — `Remundo.Reprocessor` (daily CronJob, `Forbid`) resubmits
  poison messages by strategy. Backlog growth = job failing, or truly-dead
  messages recycling on the retry-count config.
- **Read-model staleness** — Synchroniser lag makes the whole UI silently
  stale with no error anywhere; detect by comparing projection position to
  stream head. replicas=1, so a crash-loop stalls everything.
- **`Remundo.Terminator`** — GDPR purge worker, also replicas=1; crash-loop =
  purge backlog. Stream deletes "occasionally fault under load" (inline
  comment) with bounded-parallelism retries.
- **KurrentDB health** — 2 of the 9 real postmortems are EventStore
  incidents. Hourly/daily backups + nightly scavenge run as CronJobs; the
  3-shard migration is live context.
- **ArgoCD fleet health** — sync status `Unknown` fleet-wide = repo
  credential problem (a stale PAT secret silently shadowing the GitHub App
  secret broke sandbox syncing for a year); `ComparisonError: repository not
  found` on a private repo means credential, not missing repo.
- **AKS upgrades** — stall on "Insufficient vcpu quota" for surge nodes
  (`az vm list-usage`); single-node pools with `maxUnavailable:1` take their
  workloads down (sandbox's `argo`/`logs` pools = ArgoCD/logging outage).
- **Maintenance banner** — three UTC env vars on the `remundo-platform`
  ConfigMap, set by PR to the overlay's `patches/config-map.yaml`: the
  "tell users about an incident" lever.
- Daily checklist: prod sanity pipeline, DLQs, app health, all-namespaces
  pod scan from the jumpbox, ArgoCD degraded apps
  (`docs-int/docs/operations/production-duty/README.md`).

## Scepticism facts (things that lie here)

- `TinyHealthCheck` (port 3000, ~13 worker services) proves only that the
  worker loop runs — **not** Service Bus / KurrentDB reachability. A
  "healthy" pod can be fully disconnected.
- Sandbox looking dead or empty is (usually) intentional — check cluster
  power state and the monthly reset before diagnosing.
- "Staging" is not infrastructure-isolated from prod.

## Runbook candidates (seed `act_on_known`)

1. DLQ backlog: peek → classify poison vs transient → resubmit via
   Reprocessor strategy / park true poison.
2. Synchroniser lag: position vs head → restart → verify catch-up rate.
3. ArgoCD app degraded or fleet `Unknown`: credential check first, then
   diff/rollback.
4. KurrentDB scavenge/backup CronJob failures.
5. "Sandbox is down": power-state check, expected-state short-circuit.
6. Maintenance banner on/off via ConfigMap PR.

## Watch out

- `plans/scaleway-migration.md` exists — a possible move off Azure. Keep
  the cloud target provider-pluggable (DESIGN.md, targets).
- The estate is mid-migration on several axes (EventStore→KurrentDB shards,
  ES client nest v7→v9, ACR→GHCR, PAT→GitHub App credentials): expect
  drift between services; never assume one service's pattern generalizes.

## Authoritative sources (point the agent's memory here)

- `Remundo.Iac/cluster-state-management/argocd-project/bootstrap/README.md` — GitOps design
- `docs-int/docs/operations/production-duty/README.md` — the on-call checklist
- `docs-int/docs/policies-and-controls/incident-reports/` — 9 real postmortems + template
- `docs-personal/OPS.md` — tribal knowledge (unofficial, corroborated, very concrete)
- `docs-int/docs/devops/envs/sandbox.md` — sandbox ephemerality
- `docs-int/docs/infrastructure/monitoring/README.md` — monitoring stack
