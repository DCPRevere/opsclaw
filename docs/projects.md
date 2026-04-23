# Projects

A **Project** is the top of the OpsClaw hierarchy. It represents a product, service line, or organisational unit — the thing you are reasoning about, not the thing you connect to.

> For the level below this one, see [environments.md](environments.md). For the overall model, see [hierarchy.md](hierarchy.md).

## What a Project is

A Project is a name, a description, and the shared context that applies everywhere inside it. It does not hold credentials, does not open connections, and does not carry autonomy. Its job is to group Environments under a single operational identity.

Typical Projects:

- `shopfront` — a customer-facing web app
- `data-platform` — an internal analytics platform
- `payments-api` — a single service owned by one team

A Project is **not** a host, a cluster, or a cloud account. Those are Targets or attributes of Targets.

## What belongs on a Project

| Field | Purpose |
|---|---|
| `name` | Unique identifier used in addresses (`shopfront/prod/web-1`). |
| `description` | Short human-readable summary. |
| `context_file` | Markdown file prepended to the agent's prompt for every operation inside this Project. |
| `owners` | Optional list of teams or individuals responsible. Used by escalation. |

## What does not belong on a Project

- Credentials. They live on Targets.
- Autonomy levels. They live on Environments (overridable per Target).
- Endpoint pools (Loki, ELK, Prometheus, PagerDuty). They are Environment-scoped so dev and prod cannot leak into each other.
- Hosts, clusters, IPs. Those are Targets.

## Context cascade

A Project's `context_file` is the outermost layer of the agent's context. When the agent acts on `shopfront/prod/web-1`, its system prompt includes:

1. `shopfront` Project context
2. `prod` Environment context
3. `web-1` Target context

This is the feature that earns the hierarchy its keep. Project-level context holds things that are true everywhere — architecture overview, tech stack, on-call rotation link, runbook index. Environment- and Target-level contexts layer on the specifics.

## Multi-project setups

One OpsClaw instance managing two Projects is a first-class case:

```
shopfront/
  prod/          web-1, web-2, db-primary, ...
  staging/       web-1, db
data-platform/
  prod/          eks-main, airflow-vm, bastion
  dev/           dev-cluster
```

Cross-project actions are always explicit — the agent never silently acts on one Project while reasoning about another. The audit log's `PROJECT=` field makes cross-project activity easy to review in one chain.

## Separation vs. isolation

Separate Projects share one config file, one encryption key, and one OpsClaw process. If your threat model requires isolating credential material between Projects (for example, a regulated product next to an unregulated one), run two OpsClaw instances with separate config directories. Projects provide logical separation, not cryptographic isolation.

## See also

- [hierarchy.md](hierarchy.md) — the full model
- [environments.md](environments.md) — the level below
- [targets.md](targets.md) — the connection layer
