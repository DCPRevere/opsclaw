---
type: adr
status: accepted
last-reviewed: 2026-04-23
relates-to:
  - crates/opsclaw
  - docs/hierarchy.md
  - docs/projects.md
  - docs/environments.md
  - docs/targets.md
---

# ADR-005: Project → Environment → Target Hierarchy

**Status:** Accepted

**Date:** 2026-04-23

## Context

OpsClaw's current config uses a flat `[[projects]]` list. Each entry is a
named connection endpoint with a credential set, connection type (SSH, local,
Kubernetes), autonomy level, probes, and data sources. The `ProjectConfig`
name is historical — what the struct describes is closer to a connection
*target* than a project.

A flat list conflates three independent concerns:

- **Product context** — what the agent is reasoning about (product, runbooks).
- **Policy** — what the agent is allowed to do (autonomy, escalation, shared
  endpoint pools like Loki/ELK/Prometheus/PagerDuty).
- **Connection** — how the agent reaches the endpoint (credentials, address).

Operationally these diverge. A single OpsClaw instance managing two products
across dev/staging/prod with N hosts per tier needs policy scoped to the tier
(prod is `approve`, dev is `auto`), context scoped to the product, and
credentials scoped to the individual host. The flat list forces all three
onto a single record, which pushes workarounds like per-host autonomy
duplication and ambiguous endpoint-pool ownership (top-level
`loki`/`elk`/`prometheus`/`pagerduty` vs. per-entry `data_sources`).

## Decision

Adopt a three-level hierarchy:

```
Project            product or service line
 └── Environment   policy boundary (dev, staging, prod)
      └── Target   one addressable endpoint
```

**Project** holds product-level context and ownership. Does not hold
credentials, autonomy, or endpoints.

**Environment** holds policy: default autonomy, escalation, notification
routing, and shared endpoint pools (Loki, ELK, Prometheus, PagerDuty).
Environment is the boundary that prevents dev and prod from referencing each
other's infrastructure.

**Target** holds one addressable endpoint: one credential set, one connection
type, one audit identity. Targets within an Environment can freely mix
connection types (SSH hosts alongside a Kubernetes cluster alongside a
bastion).

Full model, including nomenclature rules and decision tests, is documented in
[hierarchy.md](../../hierarchy.md), [projects.md](../../projects.md),
[environments.md](../../environments.md), and [targets.md](../../targets.md).

### Invariants

1. One Target = one credential set = one audit identity.
2. Environment is policy; Target is connection. Do not mix.
3. Secrets never sit in cleartext at rest.
4. Config declares endpoints; runtime discovers everything else (pods,
   processes, services).

### Addressing

Targets are addressed as `project::environment::target`, with shortenings
permitted only when unambiguous. Ambiguous short addresses are a
user-facing error, never silently disambiguated. `::` was chosen as the
separator because names are constrained to `[a-z0-9][a-z0-9-]*` and cannot
contain it.

### Resolution

All consumers go through `OpsConfig::resolve_target(path)` once it exists.
Hand-walking `config.targets` is disallowed after Phase 5b. The resolver
returns a `ResolvedTarget` with already-cascaded autonomy, endpoints, and
context.

### Autonomy cascade

Environment sets the default; Target may override. Overrides are
**restrictive-only** — a Target may tighten (`auto` → `approve`) but never
loosen. The override field is spelled `autonomy_override` to make it visible
at read time.

### No backwards compatibility

OpsClaw is not yet in production use. Each phase is a hard rename: no
`#[serde(alias)]` escape hatches for old names, no loader branches for mixed
configs, no deprecation warnings. The flat `[[projects]]` list is renamed,
then replaced, then supplanted — with no intermediate form preserved.

## Phased rollout

Each phase is a mergeable change that compiles and passes tests.

- **Phase 0 (this ADR)** — record the decision.
- **Phase 1** — rename `ProjectConfig` → `TargetConfig`, `ProjectType` →
  `ConnectionType`, `OpsConfig.projects` → `OpsConfig.targets`. User-facing
  `opsclaw project` CLI becomes `opsclaw target`. Behavioural no-op.
- **Phase 2** — schema hygiene. Type `escalation` and `databases`. Replace
  `min_severity: String` with `AlertSeverity`. Drop legacy `OpsClawAutonomy`
  aliases (`observe`, `suggest`, `act_on_known`, `full_auto`). Add golden-file
  config-parsing fixtures.
- **Phase 3** — add Kubernetes `context: Option<String>` to `TargetConfig`.
- **Phase 4** — document endpoint-pool destiny (no code change). Freezes the
  decision that `loki`/`elk`/`prometheus`/`pagerduty` will move to
  Environment-scoped pools in Phase 5, while Target-unique sources stay on
  the Target.
- **Phase 5** — introduce `EnvironmentConfig`. Move root-level endpoint pools
  into `EnvironmentConfig::endpoints`. Replace `OpsConfig.targets` with
  `OpsConfig.environments: Vec<EnvironmentConfig>` where each Environment
  holds its own `targets: Vec<TargetConfig>`. Add `resolve_target`.
- **Phase 6** — introduce `ProjectConfig` (new meaning: the top-level product
  wrapper). Replace `OpsConfig.environments` with
  `OpsConfig.projects: Vec<ProjectConfig>`. Extend `resolve_target`.
- **Phase 7** — audit log: add `PROJECT=`, `ENV=`, `TARGET=` fields to every
  entry. Strictly additive; hash chain unchanged.

## Consequences

**Breaking changes.** Phases 1, 5, and 6 each invalidate existing config
files. Users must rewrite configs when upgrading past each phase. This is
acceptable because OpsClaw has no production users.

**Expanded validation surface.** The loader must reject:
- Ambiguous short-address references.
- Cross-Environment endpoint references.
- Target-level autonomy overrides that loosen the Environment default.
- Names containing `::`, whitespace, `/`, or mixed case.

**Resolver is load-bearing.** Once `resolve_target` ships (Phase 5b), every
tool call, scan, and audit entry flows through it. Its correctness is the
correctness of the hierarchy.

**Audit log schema bump.** Phase 7 adds fields without removing any.
Downstream log readers that whitelist fields must be updated; readers that
tolerate unknown fields need no change.

## Alternatives considered

**Keep flat, add tags.** Reject: tags without a typed hierarchy provide no
loader-enforced boundaries. A dev Target could still reference prod
endpoints.

**Two levels only (Project → Target, skip Environment).** Rejected because
the most valuable policy boundary (autonomy split between tiers) has no home.
Targets would carry Environment as a tag, leaking the same
conflation the hierarchy exists to prevent.

**Four levels (Project → Environment → Cluster/Pool → Target).** Rejected as
speculative. Region and cluster pooling can be expressed as Target naming
conventions or a future `ssh-pool` Target type without a dedicated level.
Adding a level is cheaper than removing one.

## See also

- [docs/hierarchy.md](../../hierarchy.md) — model overview.
- [docs/projects.md](../../projects.md) — Project level.
- [docs/environments.md](../../environments.md) — Environment level.
- [docs/targets.md](../../targets.md) — Target level.
