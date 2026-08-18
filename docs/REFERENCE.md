# Reference Deployment Profile

An intentionally generic estate used to shape OpsClaw's tests and examples.
It is not a description of a real organization.

## Topology

- Kubernetes environments: dev, sandbox, staging, and prod.
- Staging and prod may share a physical cluster but use separate
  namespace-scoped credentials and separate OpsClaw targets.
- Sandbox may be intentionally stopped or ephemeral.
- Access may require a jump host.
- Workloads use queues, an event store, search/log storage, metrics, and
  GitOps delivery.

## Operational signals

- Queue backlog and dead-letter growth.
- Projection lag between an event stream and read models.
- Crash-looping or unready workloads across the target's configured scope.
- Backup, maintenance, and scheduled-job failures.
- GitOps sync or repository-credential failures.
- CPU, memory, disk, and quota pressure.

Health endpoints and aggregate metrics are weak evidence on their own. A
process can be alive while its dependencies are unavailable, and a shared
cluster does not make two namespaces one environment.

## Runbook examples

1. Inspect and classify a dead-letter backlog.
2. Measure projection lag, restart a worker, and verify catch-up.
3. Diagnose a degraded GitOps application and roll back if approved.
4. Check backup or maintenance job failures.
5. Confirm expected state before treating an unreachable sandbox as an
   outage.
