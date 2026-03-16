# Dev

How to turn the ZeroClaw fork into OpsClaw.

## What ZeroClaw already gives us

- Trait-driven plugin architecture (Provider, Tool, Channel, Memory, Sandbox, Observer)
- Cron scheduler with cron expressions, fixed intervals, one-shots, per-job tool allowlists
- Daemon mode with supervised components (gateway, channels, scheduler, heartbeat)
- 13 LLM providers, 25+ channel adapters (Telegram, Slack, Email already work)
- Security policy engine with autonomy levels, credential scrubbing, sandbox backends
- Prometheus and OpenTelemetry observability
- SQLite memory backend with keyword search
- Single binary, low footprint, runs on a cheap VPS

## What we build

Phases are ordered by dependency — each one builds on the last. The goal is a working end-to-end MVP (setup → scan → monitor → alert) as fast as possible.

### Phase 1: MVP — setup, scan, monitor, alert

Everything needed for a user to run `opsclaw setup`, point it at a server, and get alerts when something looks wrong.

#### 1a. Target config schema

Extend ZeroClaw's config with a `[[targets]]` section. Parsing, validation, loading.

```toml
[[targets]]
name = "prod-web-1"
type = "ssh"
host = "203.0.113.10"
user = "opsclaw"
key = "/etc/opsclaw/keys/prod-web-1"
autonomy = "observe"
context_file = "context/prod-web-1.md"

[[targets]]
name = "this-box"
type = "local"
autonomy = "observe"
context_file = "context/this-box.md"
```

Two target types for MVP: `ssh` and `local` (sidecar). Each gets its own autonomy level and freeform context file.

#### 1b. Secret store

Needed before anything else touches credentials. SSH keys, notification tokens, DB passwords — all go through here.

`opsclaw secret set` encrypts and stores credentials locally. Config references secrets by name, never by value. Resolved at runtime.

```
opsclaw secret set slack-webhook
> URL: https://hooks.slack.com/services/...
```

Storage: encrypted file on disk. Same approach on VPS, Docker, or Kubernetes. Users can optionally integrate with Vault or cloud KMS, but the default is self-contained.

Depends on: nothing. Build this first.

#### 1c. SshTool

Implement the `Tool` trait. Uses `russh` or `async-ssh2-lite` for async SSH.

Parameters: target name (resolved from config), command to run. Returns stdout, stderr, exit code.

The tool must:
- Resolve the target from config (host, user, key path)
- Resolve SSH key from the secret store
- Never expose the SSH key contents to the LLM
- Respect autonomy level — some commands are read-only (allowed at observe), some are writes (require higher levels)
- Log every command to the audit trail
- Enforce a configurable timeout per command
- Support both interactive (allocate PTY) and batch modes

Depends on: 1a (target config), 1b (secret store).

#### 1d. Discovery scan

A built-in routine, not a tool the LLM calls directly. Runs on first connect and on demand.

Uses SshTool (or local commands in sidecar mode) to run read-only commands:
- `ps aux`, `ss -tlnp` — processes and ports
- `docker ps`, `docker inspect` — containers
- `systemctl list-units` — systemd services
- `journalctl --list-boots` — log availability
- `df -h`, `lsblk` — disk
- `cat /etc/os-release` — OS info
- Scan `/var/log` for known log files
- Check for Postgres, MySQL, Redis on standard and non-standard ports

Produces a structured target snapshot stored in memory. The user reviews and corrects it.

Depends on: 1c (SshTool).

#### 1e. Notification channel setup

ZeroClaw already has channel adapters for Telegram, Slack, Discord, Email, webhook. What's missing is the guided CLI setup: "here's how to create a Telegram bot, paste the token here."

The setup flow walks the user through getting credentials for their chosen channels and stores them via the secret store. Multiple channels supported with different roles (e.g. email for digests, Slack for urgent alerts).

Depends on: 1b (secret store). Uses existing ZeroClaw channel code.

#### 1f. Basic monitoring loop

A periodic sweep using ZeroClaw's existing scheduler. Each check is a cron job of type `Agent` with:
- A system prompt that includes the target's snapshot and context
- `allowed_tools` restricted to `ssh` (or local) plus `memory_recall`, `memory_store`
- `session_target = "Isolated"` so checks don't pollute each other
- A delivery config pointing to the notification channel

"Every 5 minutes, SSH in, check containers are running, compare against snapshot, alert if something's wrong."

This is the minimum viable monitoring. It's a periodic sweep only — no event streams, no log tailing, no baseline learning yet.

Depends on: 1c (SshTool), 1d (scan snapshot to compare against), 1e (somewhere to send alerts).

#### 1g. `opsclaw setup` CLI

The glue. An interactive terminal session that ties 1a–1f together:

1. Where am I running? (same box / remote)
2. If remote: collect SSH details, test connection, store key
3. Run discovery scan, show results, user confirms or corrects
4. User adds target context for anything the scan can't infer
5. Choose autonomy level
6. Set up notification channels
7. Configure check interval
8. Write config file, start monitoring

Extends ZeroClaw's existing `onboard` command (which handles provider/model setup). `opsclaw setup` adds the target, scan, context, autonomy, and notification steps.

Depends on: everything above.

#### MVP build order

```
1b secret store
     ↓
1a target config ──→ 1c SshTool ──→ 1d discovery scan
                                         ↓
1e notification setup ──────────→ 1f basic monitoring loop
                                         ↓
                                  1g opsclaw setup CLI
```

At the end of Phase 1, a user can: install OpsClaw, run `opsclaw setup`, point it at their server, see what's running, get alerts on Slack/Telegram/email when something changes or goes down. Observe mode only.

### Phase 2: Deeper monitoring and Kubernetes

Build on the MVP with richer monitoring and a new target type.

#### Event stream (real-time)

Subscribe to continuous event sources:
- **Docker:** `docker events` stream for container state changes
- **systemd:** `journalctl -f` for service failures

Catches things the moment they happen, instead of waiting for the next periodic sweep.

#### Log sources

Add support for reading logs from multiple sources:

- **Docker** — `docker logs` via the Docker socket (real-time)
- **systemd** — `journalctl` over SSH
- **Files** — tail `/var/log/whatever` over SSH
- **External log stores** — Elasticsearch, Loki, CloudWatch, etc. via API

External stores are often the better source — more history, structured fields, cross-service search. If the user has Filebeat shipping to Elasticsearch, OpsClaw should use that as primary and fall back to container/file logs for real-time tailing.

Credentials for external log stores go through the secret store.

#### KubeTool

Implement the `Tool` trait. Uses `kube-rs` for async Kubernetes API access.

OpsClaw runs as a pod with a ServiceAccount. Permissions granted via RBAC — read-only ClusterRole for observe mode, expanded for higher autonomy levels.

Capabilities by autonomy level:
- **Observe:** get/list/watch pods, services, events, nodes, configmaps, deployments, replicasets, statefulsets, daemonsets. Read pod logs.
- **Suggest:** same, but can propose actions for user approval.
- **Act on known:** exec into pods, restart deployments, scale replicas — matched runbook actions only.
- **Full auto:** all of the above plus novel remediation.

The user creates RBAC resources themselves — OpsClaw walks them through it during onboarding but can't bootstrap its own permissions.

Adds a `kubernetes` target type, Kubernetes discovery scan, and Kubernetes event stream.

#### External probes

Are your endpoints actually reachable from outside? Health endpoint probes, TLS certificate checks, DNS resolution. May need to run from a different location than the target.

#### Baseline learning

Extend the memory backend to store time-series observations:
- CPU, memory, disk usage at each check
- Request rates, error rates, response times (if the app exposes them)
- Container restart counts
- Postgres connection counts, replication lag

The LLM doesn't process raw time-series. A lightweight stats module computes rolling averages and standard deviations. The LLM sees: "CPU is at 85%, normally 40% ± 5% at this time of day" — enough to reason about.

### Phase 3: Diagnosis and remediation

#### Incident memory

A new memory category (`MemoryCategory::Incident`) with structured fields:
- Timestamp
- Target
- Symptoms (what was observed)
- Diagnosis (what the LLM concluded)
- Actions taken
- Outcome (resolved, escalated, unresolved)
- Resolution notes

When the LLM diagnoses a new issue, it searches incident memory first: "have I seen this before?" If yes, skip straight to the known fix (if autonomy allows).

#### Runbooks

Executable remediation procedures. Start with a hybrid format: structured steps with freeform annotations. The LLM can both follow and update them when it discovers a better approach. "Living runbooks."

Runbook execution respects autonomy levels. At "suggest," present steps and wait for approval. At "act on known," run them and report after. At "full auto," also create new runbooks from novel fixes.

#### Autonomy enforcement

Map OpsClaw's four levels to ZeroClaw's SecurityPolicy:

| OpsClaw level | SecurityPolicy.autonomy | Tool restrictions |
|---|---|---|
| Observe | Conservative | SSH read-only commands only |
| Suggest | Interactive | All SSH, but approve before writes |
| Act on known | Interactive + runbook | Auto-execute matched runbooks |
| Full auto | Autonomous | All tools, novel fixes allowed |

Per-target and per-action-category overrides.

### Phase 4: Escalation and reporting

#### Escalation engine

When OpsClaw can't fix something or autonomy doesn't allow it:
1. Package the diagnosis: what happened, what was checked, what was tried, what the likely cause is
2. Send to the primary on-call via the configured channel
3. Wait N minutes for acknowledgement
4. If no response, escalate to secondary
5. Keep retrying with increasing urgency

State machine layered on top of ZeroClaw's channel system.

#### Digests and reports

Periodic summaries: "In the last 24 hours: 3 health checks found anomalies, 1 was auto-resolved (container restart), 2 are being monitored. Disk usage on prod-web-1 is trending up — 78% now, projected full in 12 days."

Delivered via the configured channel on a schedule (daily digest, weekly summary).

### Phase 5: Polish

- Rename all ZeroClaw references to OpsClaw (binary name, config paths, docs)
- Strip the README and docs back to OpsClaw's scope
- Web dashboard for incident history and audit log (ZeroClaw's gateway gives us the API layer)
- Database diagnostic tools (Postgres read-only queries via a new `DatabaseTool`)

## Open questions

- Rust contribution barrier: is this a problem for the project? Most SRE/DevOps people know Python or Go, not Rust.
- Upstream tracking: do we track ZeroClaw upstream or hard-fork? Tracking means less maintenance but risk of conflicts. Hard-fork means we own it but carry all the weight.
- Testing: how do we test SSH-based tools? Probably a local Docker container that OpsClaw SSHes into. Integration test harness needed early.
- External probes: where do they run? If OpsClaw is inside the cluster, it can't check external reachability from outside. Needs a separate probe, or a second OpsClaw instance, or a lightweight external ping service.
- Secret store encryption key: where does the master key live? If it's on disk next to the encrypted store, it's security theatre. Options: derive from a passphrase at startup, use a hardware key, use cloud KMS.
