# OpsClaw — Product Brief

This document describes what OpsClaw is aiming for, independent of the current
implementation. It is written for an agent (or human) building OpsClaw fresh,
without the zeroclaw fork. The current repo is the reference for *behaviour*;
this brief is the reference for *intent*. Where the two conflict, this brief wins.

## 1. Mission

OpsClaw is an autonomous SRE agent. It connects to real infrastructure —
servers over SSH, Kubernetes clusters via kubeconfig, managed resources like
Postgres, RabbitMQ, Cloudflare — and does what a competent on-call engineer
does: notices something is wrong, confirms the signal with diagnostics, forms
a hypothesis, then either fixes it within policy or escalates to a human with
a structured, useful summary.

It ships as a single Rust binary, runs as a long-lived daemon, and is safe
enough to point at production: every remote command is audited, every secret
is encrypted at rest, autonomy is bounded per-target, and there is an
emergency stop.

The one-line test of the product: **given a real fault injected on a real
target, does the daemon detect it, name it correctly, notify once with an
accurate structured payload, and stay silent otherwise?** (This is literally
the acceptance test — see §9.)

## 2. Why a rebuild

OpsClaw was a fork of zeroclaw, a general-purpose agent runtime. The fork
provided the agent loop, providers, channels, memory, and gateway for free,
but the costs have outgrown the benefits:

- **Merge burden.** Tracking upstream means continual merges and a hard
  discipline of never touching `zeroclaw-*` crates, which forces workarounds.
- **Misfit hooks.** SRE tools are injected through a hook named for hardware
  peripherals (`register_peripheral_tools_fn`) because that was the only slot
  exposed. The upstream `escalate_to_human` tool doesn't work from heartbeat
  worker runs, so OpsClaw ships a parallel `opsclaw_notify` tool as a
  workaround. These are fork scars, not design.
- **Generic-runtime baggage.** The workspace carries robotics crates,
  hardware peripherals, WhatsApp/Matrix channels, a TUI, skill marketplaces —
  surface area OpsClaw doesn't need but must build, test, and merge around.
- **Vocabulary drift.** The fork accumulated two autonomy vocabularies
  (§5) and duplicated concepts (config wizard vs upstream onboard) because
  the boundary prevented unifying them.

The rebuild keeps the product (this brief) and discards the runtime coupling.
An agent loop with tool dispatch, an LLM provider layer, and a scheduler is
now cheap to build directly; the SRE domain model is the valuable part.

## 3. The shape of the system

One daemon, four concerns:

1. **Autonomous loop (heartbeat).** The core. A persistent task list (one
   scan task per project, seeded at first boot, user-editable) is ticked on
   an adaptive interval. Each tick, the agent decides what needs running,
   runs diagnostics against targets, consolidates what it learned into
   memory, and alerts if warranted. A dead-man's switch escalates if ticks
   stop happening.
2. **Reactive inputs.** Inbound alerts (webhooks from Alertmanager,
   PagerDuty, etc.) and operator chat (Slack/Telegram/CLI `opsclaw agent`)
   trigger the same diagnose-act-escalate behaviour on demand.
3. **Outbound notification.** Structured escalation payloads routed to
   configured channels and an escalation contact chain (§6).
4. **Operator surface.** CLI for setup, inspection, and control; an HTTP
   gateway for webhooks and a status dashboard.

The agent's behaviour on any signal is the same loop:
**confirm the signal with a diagnostic tool → correlate observations into a
hypothesis → act within policy, or escalate with a structured payload.**

## 4. Domain model

```
Project              product or service line (context: what am I reasoning about?)
 └── Environment     policy boundary — dev / staging / prod (what am I allowed to do?)
      └── Target     one machine/cluster/account = one credential set = one audit identity
           └── Resource   a system owned by that target: postgres, rabbitmq,
                          azure_service_bus, cloudflare, github, ...
```

Target types: `ssh`, `local`, `kubernetes`, `cloud` (provider + region).

Canonical addressing: `project::env::target::resource_type::name` for
resources; `project/env/target` for CLI commands, with unambiguous-prefix
fallbacks (`opsclaw ssh web-1` works if there's only one project/env).
The audit log always records the fully qualified path.

**Invariants (non-negotiable):**

1. One Target = one credential set = one audit identity.
2. Environment is policy; Target is connection. Never mix the two.
3. Secrets are referenced by name (`env:VAR` or the encrypted store) and
   never sit in cleartext at rest, in config files, in logs, or in
   tool output. Config inventory reports names/addresses/types/autonomy only.
4. Config declares targets, target-owned resources, and endpoints; the
   runtime *discovers* lower-level detail (pods, processes, services) at scan
   time rather than requiring it be declared.
5. Autonomy, escalation, and notification routing inherit down the tree
   (target overrides env overrides project). Credentials never inherit.

## 5. Autonomy and safety

Every target has an autonomy level. The current repo has two competing
vocabularies (README: `observe / suggest / act_on_known / auto`; older docs:
`readonly / supervised / full`). **The rebuild uses one — the four-level
set**, which is the more expressive:

| Level | Behaviour |
|---|---|
| `observe` | Read-only. Mutating commands are blocked and logged to a dry-run log for review. |
| `suggest` | Default for new targets. Reads auto-execute; mutations become approval requests over a channel, with a timeout that cancels. |
| `act_on_known` | Runbook-matched remediations auto-execute (the runbook is the pre-approval); everything else asks. |
| `auto` | Acts without prompting, still inside policy bounds. For trusted, well-runbooked workloads. |

Policy bounds apply at *every* level: forbidden paths, command allowlists,
workspace-only file ops, `max_actions_per_hour`, `max_cost_per_day_cents`,
and an always-on block of destructive command patterns. Per-tool/per-runbook
`auto_approve` and `always_ask` lists tune the middle levels.

**Safety mechanisms that must survive the rewrite:**

- **Audit log** — every command that touches a remote system goes through a
  hash-chained, append-only audit log. No bypass path exists, including for
  the agent's own tools. The chain structure is a stable format.
- **E-stop** — `opsclaw estop` freezes all agent action across all targets
  instantly (with optional network-kill and domain-block modes);
  `estop resume` unfreezes. This must work even when the agent is misbehaving.
- **Approval gating** — the request must carry enough context (command,
  target, risk class, hypothesis) for a human to decide from their phone.
- **Risk classification** — every command is classified (read / medium /
  high / destructive) before execution; classification, not the LLM's mood,
  drives the gating.

## 6. Escalation and incidents

When the agent confirms a problem it can't (or isn't allowed to) fix, it
escalates via a single structured notification tool. The payload is the
product's most visible artifact and must contain: severity, fully-qualified
target, the observed signals (with actual numbers), the hypothesis, and a
recommended action. It is delivered to a webhook and/or configured channels.

Escalation contacts form a priority chain: notify priority 0, wait
`ack_timeout`, escalate to the next, re-notify on `repeat_interval` until
acknowledged. Incident lifecycle: `Active → Acknowledged → Resolved` (or
`Expired` if the chain is exhausted). Incidents are queryable
(`opsclaw incidents`) and can generate a structured postmortem
(`opsclaw postmortem <id>`).

**Anti-spam is a first-class requirement**, equal in weight to detection:
one incident → one alert, deduplicated across heartbeat ticks; healthy
systems produce silence; a resolved fault does not produce trailing alerts.
The Tier 2 suite asserts this explicitly.

## 7. Runbooks

Runbooks are markdown files with TOML front matter: a trigger (alert
categories, keywords, target glob) and prose steps with `{placeholders}`
(`{target}`, `{container}`, `{service}`, `{namespace}`). They are the
mechanism by which human knowledge becomes pre-approved automation: matching
a runbook is what unlocks `act_on_known`.

Per-step failure handling (abort / continue / retry), full execution history,
and per-runbook success-rate tracking (low-success runbooks get surfaced for
review). CLI: `runbook init/list/show/run --target ... --var k=v`.

## 8. Memory

Memory is how OpsClaw gets faster at recurring problems. During diagnosis it
recalls similar past incidents and includes previous resolutions in context.
It also stores operator preferences, target context learned during scans, and
runbook outcomes.

Requirements: persistent across restarts; hybrid keyword + semantic search;
retention/archival policy; human-readable export. Backend pluggability
(SQLite default; Postgres/Qdrant/markdown as options) is nice-to-have, not
core. Workspace files (`AGENTS.md`, `MEMORY.md`, identity files) injected
into the system prompt each session carry standing instructions.

## 9. Testing philosophy — the part that must not be lost

Unit tests don't answer "does the agent actually respond to incidents
correctly?" The current repo's three-tier harness does, and it is as much
part of the product as the agent itself:

- **Tier 1** — component-level tool tests (integration tests per tool).
- **Tier 2 — the sim harness, the real acceptance test.** The full daemon
  runs against a gVisor-sandboxed target; real faults are injected
  (stress-ng CPU/memory pressure, disk-fill, SIGSTOP deadlock, log flood,
  process flapping, stopped services, composite cascades); each scenario
  declares an `expected.json`; the harness asserts the agent detected the
  fault, called the notify tool with a matching payload, and did not spam.
  Scenarios are directories with `arm.sh` / `disarm.sh` / `expected.json`,
  runnable individually or in parallel isolated slots. A silent-baseline
  scenario asserts the agent stays quiet on a healthy target.
- **Tier 3** — end-to-end flows: onboarding, daemon lifecycle, doctor, e-stop.

Known agent-behaviour gaps from the latest Tier 2 runs are requirements for
the rebuild, not trivia: the agent currently misses 4-way CPU saturation,
log-file growth, and process restart-flapping cadence. It also needs
environment scepticism (e.g. gVisor's host-bind mounts make `df` lie) —
diagnostics should evaluate writable mounts, not every mount.

## 10. Tool surface

Everything the agent can do is a `Tool` behind one trait: name, description,
JSON-schema'd args, risk class, audited execution. The shipped set:

- **Diagnostic:** `ssh` (command runner against targets), `kube`, `monitor`
  (cpu/mem/disk/proc overview), `systemd`, `docker`, `dns`, `cert`, `firewall`
- **Observability:** `prometheus`, `loki`, `elk`, `jaeger`
- **Resource/provider:** `postgres`, `rabbitmq`, `azure_service_bus`,
  `cloudflare`, `github`, `pagerduty`, `posthog` — addressed via the
  resource model in §4; error clearly rather than guess when ambiguous
- **Escalation:** the structured notify tool (§6)
- **Introspection:** `opsclaw_config` — read-only, secret-free config
  inventory so the agent answers "what do you manage?" without shelling
  into config files
- **Generic:** shell (policy-bounded), file read/write (workspace-bounded),
  memory store/recall, web search/fetch

## 11. Operator experience

- `opsclaw onboard` — first-run wizard: provider key (encrypted), channels,
  memory, gateway.
- `opsclaw config project|env|target add/list` — composable hierarchy
  wizards; each chains into the next (project → env → target). Config lives
  at `~/.opsclaw/config.toml`, managed by the wizards, hand-editable.
- `opsclaw daemon` / `status` / `doctor` / `scan <target>` /
  `dry-run-log` / `estop` / `incidents` / `postmortem` / `memory ...`.
- Gateway: webhook ingestion + status dashboard.
- LLM-provider agnostic (Anthropic, OpenAI, OpenRouter, local endpoints).

## 12. Explicitly out of scope for the rebuild

Carried by the fork but not part of the product: robotics/hardware crates
and peripherals, the TUI, the multi-channel zoo beyond what SREs use
(keep Slack, Telegram, email/webhook; drop WhatsApp/Matrix unless asked),
SkillForge-style skill marketplaces, and the umbrella re-export crates.
The A2A/agent-card protocol server and OpenShell sandbox integration are
optional extensions — design so they *can* exist (tool dispatch behind
traits, policy checks at one choke point), but don't build them first.

## 13. Definition of done

1. `onboard → config project add → doctor → daemon` works end-to-end on a
   fresh machine in under ten minutes.
2. The Tier 2 scenario suite (ported, including the currently-failing
   scenarios) passes: every fault class detected and correctly named, one
   alert per incident, silence on healthy baselines.
3. Every remote command appears in the hash-chained audit log with a
   fully-qualified target path; `estop` halts everything instantly.
4. No secret value can be found in any config file, log line, or tool
   output.
5. An operator at `suggest` autonomy can approve a remediation from a chat
   message and see it executed and audited.
