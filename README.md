# OpsClaw

**The AI that keeps your production alive while you sleep.**

OpsClaw is an autonomous SRE agent that monitors, diagnoses, and fixes your production systems — so you don't have to be on-call at 3am. Built on [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw), it's a single Rust binary (~9MB) that SSHes into your servers and takes care of them.

```
opsclaw setup
```

Point it at a server. It scans what's running, learns your stack, and starts watching. When something goes wrong, it diagnoses the issue, applies known fixes (if you've given it permission), and alerts you with a clear explanation of what happened and what it did about it.

## How It Works

```
OBSERVE → CORRELATE → DIAGNOSE → ACT → LEARN → REPEAT
```

1. **Observe** — Periodic health checks via SSH. Docker containers, systemd services, logs, disk, databases. Event streams for real-time changes.
2. **Correlate** — Compare against baselines and target context. "CPU at 85% when it's normally 40% at this time of day."
3. **Diagnose** — Search incident memory for known patterns. "Last time the worker restarted repeatedly, it was an OOM from a batch job at 02:00."
4. **Act** — Apply the fix (if autonomy allows) or escalate to you with a full diagnosis.
5. **Learn** — Record what happened, what worked, what didn't. Next time, it's faster.

## Features

- **Discovery scan** — Point OpsClaw at a box and it maps your stack automatically. Processes, ports, containers, services, databases, logs, disk, OS. No upfront config needed.
- **Multi-target** — Monitor one server or fifty. SSH from a central box, or run as a sidecar on each host.
- **Kubernetes native** — Runs as a pod with RBAC-scoped access. Watches pods, events, logs, deployments.
- **Autonomy levels** — You choose how much power to give it, per target:
  - **Observe** — monitor and report only
  - **Suggest** — diagnose and recommend, wait for approval
  - **Act on known** — apply runbook fixes automatically
  - **Full auto** — investigate and fix novel issues
- **Incident memory** — OpsClaw learns from every incident. Pattern matching gets better over time.
- **Living runbooks** — Executable remediation procedures that OpsClaw follows and updates as it discovers better approaches.
- **Append-only audit log** — Every command, every restart, every alert. Immutable. Non-negotiable.
- **Encrypted secret store** — SSH keys, tokens, DB passwords stored encrypted on disk. Config references secrets by name, never by value.
- **Alerting** — Telegram, Slack, Discord, email, webhooks. Multiple channels with different roles (email for digests, Telegram for urgent).
- **Pull-based observability** — Queries existing telemetry backends (Seq, Jaeger, Prometheus, Grafana) and CI/CD APIs (GitHub, GitLab) during diagnosis. No changes to monitored infrastructure. No OTLP receivers, no agents on targets.
- **Escalation** — If OpsClaw can't fix it, it packages a diagnosis and escalates to on-call. No response? It tries the next person.
- **BYOK** — Bring your own API keys. OpsClaw runs on your infrastructure with your LLM provider. No data leaves your network unless you want it to.
- **A2A protocol** — OpsClaw exposes a standard Agent-to-Agent API card and client. Delegate monitoring tasks to peer agents, chain OpsClaw into multi-agent workflows, or expose its capabilities to orchestrators.

## Deployment Models

### Sidecar (same box)

Simplest setup. OpsClaw runs on the server it monitors. Reads Docker socket and logs directly, no SSH needed. Downside: if the box dies, so does OpsClaw.

```toml
[[targets]]
name = "this-box"
type = "local"
autonomy = "observe"
context_file = "context/this-box.md"
```

### Remote (separate box)

OpsClaw runs on a separate VPS, a Pi, or your laptop. SSHes into targets. Survives target failures. Required for multi-target setups.

```toml
[[targets]]
name = "prod-web-1"
type = "ssh"
host = "203.0.113.10"
user = "opsclaw"
key_secret = "prod-web-1-key"
autonomy = "suggest"
context_file = "context/prod-web-1.md"
```

### Kubernetes

Runs as a Deployment with a ServiceAccount. RBAC controls what it can see and do.

```toml
[[targets]]
name = "prod-cluster"
type = "kubernetes"
namespace = "default"
autonomy = "act_on_known"
context_file = "context/prod-cluster.md"
```

## Target Context

OpsClaw knows how Postgres, Nginx, Redis, and Docker work. What it doesn't know is the specifics of *your* setup. Target context is freeform markdown — the stuff a human would tell a new SRE on their first day.

```markdown
# prod-web-1

Postgres runs on port 5433 (not default).
Main DB: app_prod, read replica: app_ro.
Nginx config is in /opt/nginx/conf, not /etc/nginx.
The app logs to /var/log/myapp/, not stdout.
Redis is used for sessions only — don't restart it lightly.

Deploy happens via GitHub Actions at ~14:00 UTC on weekdays.
Brief 502s during deploy are normal, don't alert.
```

This replaces structured "skill packs." The model is the skill layer — it just needs the site-specific knowledge that discovery can't provide.

## Security

- **Least privilege** — Dedicated `opsclaw` user per target with minimal permissions. Autonomy levels gate what commands are allowed.
- **Append-only audit log** — Every action is recorded. OpsClaw cannot modify or delete its own log entries. Hash-chained for integrity.
- **Encrypted secrets** — All credentials encrypted at rest. Referenced by name in config, resolved at runtime.
- **No cloud dependency** — Runs entirely on your infrastructure. Your keys, your data, your network.

## Architecture

OpsClaw is a fork of [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) — a Rust-first autonomous agent runtime. ZeroClaw provides:

- Trait-driven plugin architecture (`Provider`, `Tool`, `Channel`, `Memory`, `Observer`)
- 13 LLM providers, 25+ channel adapters
- Cron scheduler with per-job tool allowlists
- Security policy engine with autonomy levels
- SQLite memory backend
- Prometheus and OpenTelemetry observability
- Single binary, ~9MB, <5MB RAM

OpsClaw extends this with:

- `SshTool` — async SSH via `russh`, with audit logging and autonomy enforcement
- `KubeTool` — Kubernetes API access via `kube-rs` with RBAC-scoped permissions
- `DatabaseTool` — read-only diagnostic queries (connection counts, slow queries, replication lag)
- Target config schema (`[[targets]]` in TOML)
- Discovery scan engine
- Incident memory and living runbooks
- Escalation state machine
- `opsclaw setup` interactive onboarding

## Monitoring Layers

| Layer | What | How |
|---|---|---|
| **Event streams** | Real-time state changes | `docker events`, `journalctl -f`, Kubernetes watch |
| **Periodic sweeps** | Scheduled health checks | Cron-driven SSH commands, compare against baselines |
| **External probes** | Endpoint reachability | HTTP health checks, TLS cert expiry, DNS resolution |

## Roadmap

### Phase 1: MVP — Setup, Scan, Monitor, Alert ✅
Target config schema, encrypted secret store, SshTool (russh), discovery scan, notification channel setup, basic monitoring loop, `opsclaw setup` interactive CLI.

### Phase 2: Deeper Monitoring & Kubernetes ✅
Event streams (Docker events, journalctl -f), log source integration, KubeTool (kube-rs), external probes (HTTP, TLS, DNS), baseline learning (rolling stats, anomaly detection, disk projection).

### Phase 3: Diagnosis & Remediation ✅
Incident memory (keyword search, past incident context for LLM), living runbooks (trigger matching, step execution), three autonomy levels (dry-run/approve/auto), A2A protocol, escalation engine, daily digest.

### Phase 4: External Data Sources 🔨
Pull-based integration with existing telemetry backends and CI/CD — no changes required to monitored infrastructure. Seq, Jaeger/Tempo, Prometheus/Grafana APIs. GitHub/GitLab release and deployment history. Deploy timestamp detection via docker inspect.

### Phase 5: Polish
Web dashboard, database diagnostic tools, documentation, public release.

## Getting Started

```bash
# Install
curl -sSf https://opsclaw.io/install.sh | sh

# Set up your first target
opsclaw setup

# Or configure manually
opsclaw onboard        # LLM provider and channel setup
opsclaw secret set prod-key  # Store SSH key
vim opsclaw.toml       # Add target config
opsclaw scan prod-web-1      # Run discovery
opsclaw start          # Begin monitoring
```

## Memory Layout

```
~/.opsclaw/
├── opsclaw.toml           # Main config
├── secrets.enc            # Encrypted credential store
├── context/
│   ├── prod-web-1.md      # Target context (freeform)
│   └── prod-db-1.md
├── audit/
│   └── 2026-03-16.log     # Append-only audit trail
├── incidents/
│   └── 2026-03-16-001.md  # Incident records
├── runbooks/
│   └── container-oom.md   # Living runbooks
├── snapshots/
│   └── prod-web-1.json    # Discovery scan results
└── memory.db              # SQLite — baselines, incident memory
```

---

Copyright © 2026 D C P Revere. All rights reserved.

*OpsClaw: because your servers shouldn't need you awake to stay alive.*
