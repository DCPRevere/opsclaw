# Environments

An **Environment** is the middle level of the OpsClaw hierarchy. It is a policy boundary — the level at which OpsClaw decides what it is allowed to do, who to notify, and which shared infrastructure endpoints are in scope.

> For the levels around this one, see [projects.md](projects.md) and [targets.md](targets.md). For the overall model, see [hierarchy.md](hierarchy.md).

## What an Environment is

An Environment is a tier within a Project: `dev`, `staging`, `prod`, `canary`, `dr`, whatever your organisation uses. Every Target lives in exactly one Environment.

The reason Environment is its own level, rather than a tag on Targets, is that **policy is almost always tier-scoped in real operations**. "Prod is approve, dev is auto" is the canonical example. Making Environment a first-class level means that policy can be declared once and inherited by every Target in it.

## What belongs on an Environment

| Field | Purpose |
|---|---|
| `name` | Unique within the Project (`dev`, `prod`). |
| `autonomy` | Default autonomy for every Target (`dry-run`, `approve`, `auto`). Overridable per Target. |
| `escalation` | On-call policy for alerts originating in this Environment. |
| `notifications` | Routing for this Environment's alerts (Slack channel, PagerDuty service, Telegram chat). |
| `context_file` | Markdown prepended to the agent's prompt for operations in this Environment. |
| `endpoints` | Scoped endpoint pools — Loki, ELK, Prometheus, PagerDuty. Targets reference them by name. |

## The autonomy split

The most important thing an Environment does is set autonomy. OpsClaw supports three levels:

- `dry-run` — log proposed actions, do not execute. Read-only commands still run.
- `approve` — propose actions, wait for explicit approval before executing.
- `auto` — execute without asking.

A common shape:

```
shopfront/
  dev       autonomy = auto
  staging   autonomy = approve
  prod      autonomy = approve    # plus escalation-on-failure
```

Targets inherit their Environment's autonomy. A Target can override (for example, a single bastion host set to `approve` in an otherwise `auto` dev Environment) but overrides should be rare and loudly flagged in config review.

See [autonomy.md](autonomy.md) for how the resolved level is applied.

## Endpoint pools

Shared infrastructure — log aggregators, metrics backends, incident management — belongs at the Environment level. A dev ELK cluster and a prod ELK cluster are structurally distinct resources, and the Environment boundary enforces that the agent cannot reach across tiers during an incident.

```
environments.prod.endpoints.loki    = "loki-prod.example.com"
environments.prod.endpoints.elk     = "es-prod.example.com"
environments.dev.endpoints.loki     = "loki-dev.example.com"
```

A Target references endpoints by name within its Environment. There is no way to reference an endpoint from a different Environment — that is the point.

## Escalation

Escalation policies describe who gets paged when an action fails or an alert crosses severity thresholds. They are Environment-scoped because oncall rotations almost always differ between tiers — prod pages the oncall, dev posts to a team channel. Policies are tiered: primary contact, secondary after N minutes, manager after M minutes.

## Context cascade

An Environment's context file is layered on top of its Project's context. Use it for tier-specific facts:

- "Prod runs three regions: us-east-1, us-west-2, eu-west-1."
- "Dev uses mocked payment providers — never test with real card numbers."
- "Staging is refreshed from a prod snapshot every Sunday 02:00 UTC."

Keep it short. Context that applies to just one Target belongs on the Target.

## What does not belong on an Environment

- Credentials. Each Target holds its own.
- Connection details (hosts, kubeconfigs, API URLs). Those define Targets.
- Project-wide facts (architecture, ownership). Those belong on the Project.

## Same-cluster, different-environment

One physical Kubernetes cluster can legitimately appear in two Environments:

```
staging/shared-cluster   namespace = staging,  autonomy = auto
prod/shared-cluster      namespace = prod,     autonomy = approve
```

Same kubeconfig, same API server, two Targets in two Environments. The Environment boundary — not the physical infrastructure — is what enforces the autonomy split. This pattern is common for cost-shared clusters.

## See also

- [hierarchy.md](hierarchy.md) — the full model
- [projects.md](projects.md) — the level above
- [targets.md](targets.md) — the level below
- [autonomy.md](autonomy.md) — how autonomy is resolved and applied
